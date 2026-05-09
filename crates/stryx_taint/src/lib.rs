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
    pub reaches_db_sink_unsanitized: bool,
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
