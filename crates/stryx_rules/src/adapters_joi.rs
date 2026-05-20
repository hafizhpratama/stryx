//! `validation/joi` adapter — sanitiser patterns for Joi, the
//! long-standing schema validator most commonly seen in Express + Node
//! codebases that pre-date the Zod / Valibot wave.
//!
//! Joi's runtime surface exposes three entry points whose syntactic
//! shapes split cleanly between *method-on-receiver* and
//! *namespace-member* call forms. From the engine's perspective each is
//! a [`SanitizerKind::SchemaParse`]: the call inspects an input against
//! a schema and the surviving control-flow branch carries a validated
//! value. Modelling all three uniformly keeps Joi interchangeable with
//! `zod`, `class-validator`, `valibot`, etc. so the generic
//! `flow/unvalidated-body-to-db` rule treats them the same way.
//!
//! - `schema.validate(input)`        — sync-or-async (depends on the
//!   `{ async: true }` option); returns `{ value, error }`. Method-on-
//!   receiver shape: the receiver is the schema object built via
//!   `Joi.object({...})` / `Joi.string()` chains.
//! - `Joi.assert(input, schema)`     — throws on invalid input.
//!   Namespace-member call rooted at the imported `Joi` default
//!   binding.
//! - `Joi.attempt(input, schema)`    — throws on invalid input and
//!   returns the validated value. Same namespace-member shape as
//!   `assert`.
//!
//! ## Matcher shapes and false-positive trade-off
//!
//! The two `Joi.*` patterns use [`AstMatcher::NamespaceCall`], which
//! requires a bare-ident `Joi` receiver — precise enough that the
//! patterns only fire on the canonical
//! `import Joi from "joi"` + `Joi.assert(...)` shape. Aliased imports
//! (`import * as J from "joi"; J.assert(...)`) are an accepted miss;
//! a future slice can add an import-aware namespace matcher if real
//! usage demands it.
//!
//! The `schema.validate(input)` pattern uses
//! [`AstMatcher::MethodCallAnyReceiver`] keyed on `"validate"`. This
//! is the same broad-matcher trade-off that
//! [`crate::adapters_zod`] makes for `.parse` / `.safeParse`:
//! receiver identity is opaque at AST-shape level, so any
//! `<anything>.validate(...)` call is recognised as a sanitiser, not
//! only Joi schema-objects'. On the sanitiser side this is the
//! **less-safe** direction — a spurious match clears taint that wasn't
//! really sanitised, producing a *missed* finding rather than an
//! inflated one. The class-validator adapter's `.validate` matcher has
//! the same shape and the same trade-off; the two coexist because
//! profile-gating ensures the relevant adapter activates only when
//! project evidence points at that library.
//!
//! Mitigation today: this adapter activates only when the project
//! profile has surfaced a [`ValidatorHint::Joi`] entry at or above the
//! enable floor. The activation itself is the project-level evidence
//! that `.validate(...)` is far more likely to be a Joi call than an
//! unrelated helper. Outside Joi projects the patterns simply don't
//! fire.
//!
//! Mitigation later: a future slice can introduce a more constrained
//! matcher (e.g. `MethodCallOnTypedReceiver`) that consults the
//! per-file import map for a receiver whose ultimate origin is a
//! `Joi.object(...)` / `Joi.string()` chain. The substrate doesn't yet
//! support that, and threading receiver-type tracking through the hot
//! path is a non-trivial change — out of scope here.
//!
//! ## Hint identity
//!
//! Detection lives in [`stryx_index::profile::detect`] under the
//! validator family; [`ValidatorHint::Joi`] serialises as `"joi"` via
//! the enum's `serde(rename_all = "kebab-case")` rule, which is what
//! the default `is_enabled` resolution in [`crate::adapters`] compares
//! the adapter ID suffix against.
//!
//! [ADR 0014]: ../../../docs/decisions/0014-adapter-substrate-api.md
//! [`ValidatorHint::Joi`]: stryx_index::profile::ValidatorHint::Joi

use crate::adapters::{
    AdapterId, AdapterKind, AstMatcher, SanitiserPattern, SanitizerKind, StackAdapter,
};

pub struct JoiAdapter;

// =============================================================================
// Sanitiser patterns
// =============================================================================
//
// One pattern per Joi entry-point. The method-vs-namespace split is
// load-bearing: `validate` is invoked on a schema instance, while
// `assert` / `attempt` are static helpers off the `Joi` namespace. See
// the module-level note for the false-positive trade-off rationale on
// the broad `MethodCallAnyReceiver` matcher used by the `validate`
// pattern.

static SANITISERS: &[SanitiserPattern] = &[
    // `schema.validate(input)` — the most common shape in real Joi
    // codebases: `const { value, error } = userSchema.validate(req.body);`.
    // Schema receiver identity isn't tracked; the `validate` method
    // name is the signal (same trade-off as Zod's `.parse`).
    SanitiserPattern {
        id: "validation/joi/validate",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::MethodCallAnyReceiver { method: "validate" }],
    },
    // `Joi.assert(input, schema)` — throw-on-fail static helper. The
    // `NamespaceCall` shape pins the receiver to the bare-ident `Joi`
    // binding, so unrelated `<other>.assert(...)` calls (Node's
    // `assert` module, Chai's `.assert`, custom helpers) are excluded
    // by construction.
    SanitiserPattern {
        id: "validation/joi/assert",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::NamespaceCall {
            namespace: "Joi",
            member: "assert",
        }],
    },
    // `Joi.attempt(input, schema)` — throw-on-fail + returns the
    // coerced value. Same namespace-member shape as `assert`.
    SanitiserPattern {
        id: "validation/joi/attempt",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::NamespaceCall {
            namespace: "Joi",
            member: "attempt",
        }],
    },
];

impl StackAdapter for JoiAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("validation/joi")
    }
    fn kind(&self) -> AdapterKind {
        AdapterKind::Validator
    }
    fn sanitisers(&self) -> &'static [SanitiserPattern] {
        SANITISERS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stryx_index::profile::{Detected, ProjectProfile, ValidatorHint};

    #[test]
    fn joi_adapter_exposes_expected_sanitiser_patterns() {
        let sanitisers = JoiAdapter.sanitisers();
        // One pattern per Joi entry-point: `schema.validate`,
        // `Joi.assert`, `Joi.attempt`. The three-pattern surface
        // mirrors the canonical Joi public API documented at
        // https://joi.dev/api/ — pinning the count guards against
        // accidental drops during future refactors.
        assert_eq!(sanitisers.len(), 3);
        let ids: Vec<&str> = sanitisers.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"validation/joi/validate"));
        assert!(ids.contains(&"validation/joi/assert"));
        assert!(ids.contains(&"validation/joi/attempt"));

        // Every pattern must classify as SchemaParse — that's the
        // contract the generic `flow/unvalidated-body-to-db` rule
        // consults to clear UserInput taint, and what makes Joi
        // interchangeable with zod / class-validator / valibot.
        for s in sanitisers {
            assert_eq!(
                s.sanitizer,
                SanitizerKind::SchemaParse,
                "wrong SanitizerKind for {}",
                s.id
            );
            // Single matcher per pattern. Pin the count so a refactor
            // that adds an `ImportedCall` shape (Joi doesn't expose
            // top-level functions like class-validator does — `assert`
            // and `attempt` are namespace-rooted only) is caught here.
            assert_eq!(s.matchers.len(), 1, "wrong matcher count for {}", s.id);
        }
    }

    #[test]
    fn joi_adapter_is_validator_kind() {
        assert_eq!(JoiAdapter.id(), AdapterId("validation/joi"));
        assert_eq!(JoiAdapter.kind(), AdapterKind::Validator);
    }

    #[test]
    fn is_enabled_returns_true_under_joi_profile() {
        // `ValidatorHint::Joi` at 0.90 is well above the 0.60 enable
        // floor — the default `is_enabled` resolution must activate
        // the adapter. The id-suffix matching relies on
        // `ValidatorHint::Joi` serialising to `"joi"` via the enum's
        // kebab-case rule.
        let profile = ProjectProfile {
            validators: vec![Detected {
                id: ValidatorHint::Joi,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(JoiAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_yup_profile() {
        // A profile that detected Yup but not Joi — the Joi adapter
        // must stay disabled. Guards against the regression where the
        // kind/name split lets a same-kind sibling validator activate
        // the adapter.
        let profile = ProjectProfile {
            validators: vec![Detected {
                id: ValidatorHint::Yup,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!JoiAdapter.is_enabled(&profile));
    }
}
