//! `validation/yup` adapter — sanitiser patterns for Yup, a
//! TypeScript-friendly schema validator that grew out of the React form
//! ecosystem (Formik, react-hook-form) and is increasingly used
//! backend-side for request validation.
//!
//! Yup schemas are built by chaining `yup.object({...})`,
//! `yup.string().min(3)`, `yup.number().required()`, etc. From the
//! engine's perspective, every "did this value satisfy the schema?"
//! method is a [`SanitizerKind::SchemaParse`] — the call inspects the
//! argument and the surviving control-flow branch carries a validated
//! value.
//!
//! - `schema.validate(value)`      — async, returns a `Promise` that
//!   rejects on invalid. The most common backend shape:
//!   `const body = await UserSchema.validate(await req.json())`.
//! - `schema.validateSync(value)`  — sync, throws on invalid. Same
//!   throw-on-fail contract as Zod's `parse`.
//! - `schema.isValid(value)`       — async, returns
//!   `Promise<boolean>`. The call is only *truly* sanitising on the
//!   post-`true` branch; the adapter still classifies it as
//!   `SchemaParse` because the downstream control-flow check is a
//!   rule-level concern, not a pattern-recognition one. Treating it as
//!   a sanitiser is the **less-safe** direction (a missed finding when
//!   the bool isn't checked is preferable to a flood of false positives
//!   on the dominant correct-usage shape).
//! - `schema.isValidSync(value)`   — sync variant of `isValid`.
//!
//! ## Deliberately excluded: `schema.cast(value)`
//!
//! Yup's `cast` *coerces* an input toward the schema's declared types
//! (e.g. parses a string into a number, fills in defaults) but does
//! **not** validate the shape — invalid values pass through unchanged
//! or coerced to `NaN`/`undefined`. Treating `cast` as a sanitiser
//! would mask real findings: `db.users.create({ data: schema.cast(body) })`
//! is still vulnerable to whatever taint `body` carries. The patterns
//! here intentionally do not include `cast`; calls like
//! `schema.cast(body)` leave `UserInput` taint intact.
//!
//! ## Matcher shape and false-positive trade-off
//!
//! Each pattern carries a single matcher:
//! [`AstMatcher::MethodCallAnyReceiver`] keyed on the method name.
//! Receiver identity isn't tracked at the AST level — `schema.validate`,
//! `UserSchema.validate`, and `bodySchema.validate` all reduce to the
//! same method-name signal.
//!
//! The unavoidable downside: a spurious match clears taint that wasn't
//! really sanitised, producing a missed finding rather than an inflated
//! one. The four Yup method names are less commonly collided-with than
//! Zod's `parse` (no `JSON.validate`, no `Date.validateSync`), but a
//! local helper named `.validate(x)` will still false-clear under this
//! adapter.
//!
//! Mitigation today: this adapter only activates when the project
//! profile has surfaced a [`ValidatorHint::Yup`] entry at or above the
//! enable floor. Outside Yup projects the patterns simply don't fire.
//!
//! Mitigation later: a future `MethodCallOnTypedReceiver` matcher can
//! consult the per-file import map for a receiver whose ultimate origin
//! is a `yup.object(...)` / `yup.string()` chain. Out of scope here —
//! see the parallel reasoning in [`crate::adapters_zod`].
//!
//! ## Hint identity
//!
//! Detection lives in [`stryx_index::profile::detect`] under the
//! validator family; [`ValidatorHint::Yup`] serialises as `"yup"` via
//! the enum's `serde(rename_all = "kebab-case")` rule, which is what
//! the default `is_enabled` resolution in [`crate::adapters`] compares
//! the adapter ID suffix against.
//!
//! [ADR 0014]: ../../../docs/decisions/0014-adapter-substrate-api.md
//! [`ValidatorHint::Yup`]: stryx_index::profile::ValidatorHint::Yup

use crate::adapters::{
    AdapterId, AdapterKind, AstMatcher, SanitiserPattern, SanitizerKind, StackAdapter,
};

pub struct YupAdapter;

// =============================================================================
// Sanitiser patterns
// =============================================================================
//
// One pattern per method name. Each uses `MethodCallAnyReceiver`
// because the schema receiver's identity is opaque at AST-shape level
// (see the module-level note on the false-positive trade-off). The
// four method names mirror Yup's runtime validation surface
// (`validate`, `validateSync`, `isValid`, `isValidSync`); `cast` is
// deliberately excluded because it coerces without validating.

static SANITISERS: &[SanitiserPattern] = &[
    // `schema.validate(value)` — async throw-on-reject. The most
    // common backend shape:
    // `const body = await UserSchema.validate(await req.json())`.
    SanitiserPattern {
        id: "validation/yup/validate",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::MethodCallAnyReceiver { method: "validate" }],
    },
    // `schema.validateSync(value)` — sync throw-on-fail, semantically
    // equivalent to Zod's `parse`. Used in non-async contexts (CLI
    // tools, sync middleware).
    SanitiserPattern {
        id: "validation/yup/validate-sync",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::MethodCallAnyReceiver {
            method: "validateSync",
        }],
    },
    // `schema.isValid(value)` — async, returns `Promise<boolean>`. The
    // adapter pattern fires on the call itself; the downstream
    // `if (await schema.isValid(x))` gate is the rule's job to require.
    // Treating it uniformly as a sanitiser favours fewer false
    // positives over catching every misuse — see the module-level
    // trade-off note.
    SanitiserPattern {
        id: "validation/yup/is-valid",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::MethodCallAnyReceiver { method: "isValid" }],
    },
    // `schema.isValidSync(value)` — sync boolean form.
    SanitiserPattern {
        id: "validation/yup/is-valid-sync",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::MethodCallAnyReceiver {
            method: "isValidSync",
        }],
    },
    // NOTE: `schema.cast(value)` is intentionally absent. `cast`
    // coerces an input toward the schema's types but does not
    // validate; matching it as a sanitiser would clear UserInput taint
    // on still-untrusted data and mask real findings.
];

impl StackAdapter for YupAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("validation/yup")
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
    fn yup_adapter_exposes_expected_sanitiser_patterns() {
        let sanitisers = YupAdapter.sanitisers();
        // One pattern per Yup validation entry-point. The four-pattern
        // surface mirrors Yup's runtime validation API
        // (`validate`/`validateSync`/`isValid`/`isValidSync`) and
        // explicitly excludes `cast`, which coerces without
        // validating.
        assert_eq!(sanitisers.len(), 4);
        let ids: Vec<&str> = sanitisers.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"validation/yup/validate"));
        assert!(ids.contains(&"validation/yup/validate-sync"));
        assert!(ids.contains(&"validation/yup/is-valid"));
        assert!(ids.contains(&"validation/yup/is-valid-sync"));

        // `cast` must not be exposed — including it would clear
        // UserInput taint on coerced-but-unvalidated data and produce
        // missed findings on the dominant backend abuse shape
        // (`db.create({ data: schema.cast(body) })`).
        assert!(!ids.iter().any(|id| id.contains("cast")));

        // Every pattern must classify as SchemaParse — that's the
        // contract the generic `flow/unvalidated-body-to-db` rule
        // consults to clear UserInput taint, and what makes Yup
        // interchangeable with zod / class-validator / valibot / joi.
        for s in sanitisers {
            assert_eq!(
                s.sanitizer,
                SanitizerKind::SchemaParse,
                "wrong SanitizerKind for {}",
                s.id
            );
            // Single matcher per pattern — `MethodCallAnyReceiver`
            // keyed on the Yup method name. Pin the count so a
            // refactor that adds an `ImportedCall` shape (Yup re-
            // exports its factory functions but the validation surface
            // is method-only) is caught here.
            assert_eq!(s.matchers.len(), 1, "wrong matcher count for {}", s.id);
        }
    }

    #[test]
    fn yup_adapter_is_validator_kind() {
        assert_eq!(YupAdapter.id(), AdapterId("validation/yup"));
        assert_eq!(YupAdapter.kind(), AdapterKind::Validator);
    }

    #[test]
    fn is_enabled_returns_true_under_yup_profile() {
        // `ValidatorHint::Yup` at 0.90 is well above the 0.60 enable
        // floor — the default `is_enabled` resolution must activate
        // the adapter. The id-suffix matching relies on
        // `ValidatorHint::Yup` serialising to `"yup"` via the enum's
        // kebab-case rule.
        let profile = ProjectProfile {
            validators: vec![Detected {
                id: ValidatorHint::Yup,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(YupAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_zod_profile() {
        // A profile that detected Zod but not Yup — the Yup adapter
        // must stay disabled. Guards against the regression where the
        // kind/name split lets a same-kind sibling validator activate
        // the adapter.
        let profile = ProjectProfile {
            validators: vec![Detected {
                id: ValidatorHint::Zod,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!YupAdapter.is_enabled(&profile));
    }
}
