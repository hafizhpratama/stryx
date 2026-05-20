//! `validation/zod` adapter — sanitiser patterns for Zod, the most
//! widely-used TypeScript schema validator on backend stacks.
//!
//! Zod's runtime surface centres on four method calls invoked on a
//! schema object built by chaining `z.object({...})`, `z.string()`,
//! `z.number().min(0)`, etc. From the engine's perspective each call
//! is a [`SanitizerKind::SchemaParse`]: the call inspects the argument
//! against the schema and the surviving control-flow branch carries a
//! validated value.
//!
//! - `schema.parse(value)`           — sync, throws on invalid; pure
//!   throw-on-fail sanitiser.
//! - `schema.safeParse(value)`       — sync, returns
//!   `{ success: true, data } | { success: false, error }`. The call
//!   is only *truly* sanitising on the post-`success` branch; the
//!   adapter still classifies it as `SchemaParse` because that
//!   downstream control-flow check is a rule-level concern, not a
//!   pattern-recognition one.
//! - `schema.parseAsync(value)`      — async variant of `parse`.
//! - `schema.safeParseAsync(value)`  — async variant of `safeParse`.
//!
//! Modelling all four uniformly keeps Zod interchangeable with
//! `class-validator`, `valibot`, `joi`, etc. so the generic
//! `flow/unvalidated-body-to-db` rule treats them the same way.
//!
//! ## Matcher shape and false-positive trade-off
//!
//! Each pattern carries a single matcher:
//! [`AstMatcher::MethodCallAnyReceiver`] keyed on the method name.
//! Receiver identity isn't tracked at the AST level — `schema.parse`,
//! `UserSchema.parse`, and `bodySchema.parse` all reduce to the same
//! method-name signal.
//!
//! The unavoidable downside: `MethodCallAnyReceiver { method: "parse" }`
//! also fires on unrelated calls that happen to share the name —
//! `JSON.parse(text)`, `Date.parse(s)`, a custom `RouteSpec.parse(req)`
//! helper, etc. On the sanitiser side this is the **less-safe**
//! direction: a spurious match clears taint that wasn't really
//! sanitised, producing a missed finding rather than an inflated one.
//! That sits opposite the class-validator adapter's reasoning, where
//! the matched names (`validate`, `validateOrReject`, `validateSync`)
//! are uncommon enough that the relaxed shape is broadly safe.
//!
//! Mitigation today: this adapter only activates when the project
//! profile has surfaced a [`ValidatorHint::Zod`] entry at or above the
//! enable floor. The activation itself is the project-level evidence
//! that `.parse(...)` is far more likely to be Zod's schema parse than
//! `JSON.parse`. Outside Zod projects the patterns simply don't fire.
//!
//! Mitigation later: a future slice can introduce a more constrained
//! matcher (e.g. `MethodCallOnTypedReceiver`) that consults the
//! per-file import map for a receiver whose ultimate origin is a
//! `z.object(...)` / `z.string()` chain. The substrate doesn't yet
//! support that, and threading receiver-type tracking through the hot
//! path is a non-trivial change — out of scope here.
//!
//! ## Hint identity
//!
//! Detection lives in [`stryx_index::profile::detect`] under the
//! validator family; [`ValidatorHint::Zod`] serialises as `"zod"` via
//! the enum's `serde(rename_all = "kebab-case")` rule, which is what
//! the default `is_enabled` resolution in [`crate::adapters`] compares
//! the adapter ID suffix against.
//!
//! [ADR 0014]: ../../../docs/decisions/0014-adapter-substrate-api.md
//! [`ValidatorHint::Zod`]: stryx_index::profile::ValidatorHint::Zod

use crate::adapters::{
    AdapterId, AdapterKind, AstMatcher, SanitiserPattern, SanitizerKind, StackAdapter,
};

pub struct ZodAdapter;

// =============================================================================
// Sanitiser patterns
// =============================================================================
//
// One pattern per method name. Each uses
// `MethodCallAnyReceiver` because the schema receiver's identity is
// opaque at AST-shape level (see the module-level note on the
// false-positive trade-off). The four method names mirror the inline
// recogniser in `flows/unvalidated_body_to_db::call_validates_request_body`
// so substrate-driven dispatch lands as a drop-in replacement when the
// flow rule is migrated to consume `EnabledAdapters::sanitisers`.

static SANITISERS: &[SanitiserPattern] = &[
    // `schema.parse(value)` — sync throw-on-fail. The most common
    // shape in route handlers: `const body = UserSchema.parse(await
    // req.json())`.
    SanitiserPattern {
        id: "validation/zod/parse",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::MethodCallAnyReceiver { method: "parse" }],
    },
    // `schema.safeParse(value)` — sync result-object form. The
    // adapter pattern fires on the call itself; the downstream
    // `if (result.success)` gate is the rule's job to require.
    SanitiserPattern {
        id: "validation/zod/safe-parse",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::MethodCallAnyReceiver {
            method: "safeParse",
        }],
    },
    // `schema.parseAsync(value)` — async throw-on-fail. Used when
    // schemas include async refinements (`.refine(async ...)`).
    SanitiserPattern {
        id: "validation/zod/parse-async",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::MethodCallAnyReceiver {
            method: "parseAsync",
        }],
    },
    // `schema.safeParseAsync(value)` — async result-object form.
    SanitiserPattern {
        id: "validation/zod/safe-parse-async",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::MethodCallAnyReceiver {
            method: "safeParseAsync",
        }],
    },
];

impl StackAdapter for ZodAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("validation/zod")
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
    fn zod_adapter_exposes_expected_sanitiser_patterns() {
        let sanitisers = ZodAdapter.sanitisers();
        // One pattern per Zod entry-point method. The four-pattern
        // surface mirrors the inline recogniser in
        // `flows/unvalidated_body_to_db::call_validates_request_body`
        // so a future substrate migration drops in without changing
        // recognised shapes.
        assert_eq!(sanitisers.len(), 4);
        let ids: Vec<&str> = sanitisers.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"validation/zod/parse"));
        assert!(ids.contains(&"validation/zod/safe-parse"));
        assert!(ids.contains(&"validation/zod/parse-async"));
        assert!(ids.contains(&"validation/zod/safe-parse-async"));

        // Every pattern must classify as SchemaParse — that's the
        // contract the generic `flow/unvalidated-body-to-db` rule
        // consults to clear UserInput taint, and what makes Zod
        // interchangeable with class-validator / valibot / joi.
        for s in sanitisers {
            assert_eq!(
                s.sanitizer,
                SanitizerKind::SchemaParse,
                "wrong SanitizerKind for {}",
                s.id
            );
            // Single matcher per pattern — `MethodCallAnyReceiver`
            // keyed on the Zod method name. Pin the count so a
            // refactor that adds an `ImportedCall` shape (Zod doesn't
            // expose top-level functions like class-validator does)
            // is caught here.
            assert_eq!(s.matchers.len(), 1, "wrong matcher count for {}", s.id);
        }
    }

    #[test]
    fn zod_adapter_is_validator_kind() {
        assert_eq!(ZodAdapter.id(), AdapterId("validation/zod"));
        assert_eq!(ZodAdapter.kind(), AdapterKind::Validator);
    }

    #[test]
    fn is_enabled_returns_true_under_zod_profile() {
        // `ValidatorHint::Zod` at 0.90 is well above the 0.60 enable
        // floor — the default `is_enabled` resolution must activate
        // the adapter. The id-suffix matching relies on
        // `ValidatorHint::Zod` serialising to `"zod"` via the enum's
        // kebab-case rule.
        let profile = ProjectProfile {
            validators: vec![Detected {
                id: ValidatorHint::Zod,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(ZodAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_valibot_profile() {
        // A profile that detected Valibot but not Zod — the Zod
        // adapter must stay disabled. Guards against the regression
        // where the kind/name split lets a same-kind sibling
        // validator activate the adapter.
        let profile = ProjectProfile {
            validators: vec![Detected {
                id: ValidatorHint::Valibot,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!ZodAdapter.is_enabled(&profile));
    }
}
