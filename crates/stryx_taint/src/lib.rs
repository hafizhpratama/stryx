//! Cross-file taint vocabulary. Slice 2 introduces concrete summary
//! types: a per-function record of *what each parameter does to the
//! taint that flows in*. The flow rule consumes these summaries during
//! the second engine pass to follow call sites across files.

use serde::{Deserialize, Serialize};
use stryx_core::Span;

/// A taint label classifies *what kind of trust* flows through a value.
/// Labels are deliberately coarse — a rule reasons over labels, not over
/// raw expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaintLabel {
    /// Anything coming off the network: `req.body`, query string, headers,
    /// form data.
    UserInput,
    /// Authenticated user identity (post-auth subject).
    AuthSubject,
    /// Secret material: API keys, tokens, hashed-but-still-sensitive blobs.
    Secret,
    /// Database row content (may itself be tainted depending on writers).
    DbRow,
}

/// A field/index offset into a tainted parameter. Phase 1 of the
/// shape-lattice migration (ADR 0006): instead of "this whole parameter
/// is tainted," summaries record *which fields/indexes* flow to a sink.
/// Phase 2 will absorb this list into a full `Cell { xtaint, shape }`
/// tree; for now a flat list is enough to lift where-clause severity
/// and validated-field suppression beyond what whole-arg booleans can
/// express.
///
/// `Field` is JS/TS-aware: `obj.a` and `obj["a"]` yield the same
/// offset, matching Semgrep's `Ofld == Ostr` unification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Offset {
    /// Named field access: `param.field` or `param["field"]`.
    Field(String),
    /// Constant numeric index: `param[0]`.
    Index(u32),
    /// Non-constant index — `param[i]` where `i` isn't a literal.
    /// Acts as the wildcard offset; collapses into Phase 2's `Oany`.
    Any,
}

/// What happens to taint that enters a function through a single
/// parameter. Per-rule for now — the flow rule populates this for the
/// `UserInput` label.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParamFlow {
    /// Position-indexed name of the parameter (informational).
    pub name: String,
    /// True iff there is a control-flow path from this parameter to a
    /// DB write call where no sanitizer (`.parse`/`.safeParse`) cleared
    /// the taint along the way.
    ///
    /// Slice-1 transitional state per ADR 0006 — coexists with
    /// [`tainted_offsets`](Self::tainted_offsets) until slice 2 starts
    /// populating offsets and slice 3 collapses this field into a
    /// derived accessor (`!self.tainted_offsets.is_empty()`).
    pub reaches_db_sink_unsanitized: bool,
    /// Which field/index offsets of this parameter flow to a sink, if
    /// the rule populating the summary records that detail. Empty list
    /// means either "no taint reaches a sink" or "the rule has not yet
    /// migrated to record offsets" — disambiguate via
    /// [`reaches_db_sink_unsanitized`](Self::reaches_db_sink_unsanitized)
    /// during the slice-1/2 window.
    ///
    /// See ADR 0006 (shape lattice) for the migration plan.
    #[serde(default)]
    pub tainted_offsets: Vec<Offset>,
    /// True iff the parameter's value flows back to the function's
    /// return value (directly, or via member access / object/array
    /// literal containment). Helpers like `toPaymentStatus(input)`
    /// that only return constant strings have this set to false, so
    /// callers don't propagate taint through them.
    #[serde(default)]
    pub propagates_to_return: bool,
    /// Where the sink lives, if known. Used so call-site findings can
    /// point readers to the actual write inside the callee.
    pub sink_span: Option<Span>,
}

/// Summary of a single exported function. The flow rule produces one of
/// these per top-level/exported function during the extract pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedFunctionSummary {
    pub name: String,
    pub params: Vec<ParamFlow>,
    /// Span of the function definition itself, for diagnostics.
    pub span: Span,
    /// True iff the function's body contains a recognised auth-helper
    /// call (`getServerSession`, `auth`, `getSession`, …). Consumed by
    /// `flow/auth-bypass-via-wrapper` to tell apart wrappers that
    /// actually verify authentication from no-op wrappers that just
    /// claim to.
    #[serde(default)]
    pub contains_auth_check: bool,
    /// True iff the function's body validates `req.body` against a
    /// schema before calling its inner handler — the inverse of
    /// `contains_auth_check`. Consumed by `flow/unvalidated-body-to-db`
    /// to suppress body-taint sourcing inside handlers wrapped by a
    /// `validate(handler)`-shaped function whose body calls
    /// `<schema>.parse(req.body)` or `<schema>.safeParse(...)`.
    #[serde(default)]
    pub validates_request_body: bool,
}

impl ExportedFunctionSummary {
    /// True if calling this function with a tainted value at parameter
    /// position `idx` would result in that taint reaching a DB sink.
    pub fn taints_through_param(&self, idx: usize) -> bool {
        self.params
            .get(idx)
            .is_some_and(|p| p.reaches_db_sink_unsanitized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_serde_roundtrips() {
        let offsets = vec![
            Offset::Field("body".into()),
            Offset::Field("where".into()),
            Offset::Index(0),
            Offset::Any,
        ];
        let json = serde_json::to_string(&offsets).unwrap();
        let back: Vec<Offset> = serde_json::from_str(&json).unwrap();
        assert_eq!(offsets, back);
    }

    #[test]
    fn paramflow_with_empty_offsets_deserializes_from_pre_slice1_json() {
        // Pre-slice-1 cache entries have no `tainted_offsets` key.
        // They must still deserialize, with the field defaulting to
        // empty — a safe under-approximation per the slice-1
        // transitional contract. Guards the cache-rollover behaviour
        // from ADR 0005.
        let pre = r#"{
            "name": "handler",
            "reaches_db_sink_unsanitized": true,
            "propagates_to_return": false
        }"#;
        let pf: ParamFlow = serde_json::from_str(pre).unwrap();
        assert!(pf.reaches_db_sink_unsanitized);
        assert!(pf.tainted_offsets.is_empty());
    }
}
