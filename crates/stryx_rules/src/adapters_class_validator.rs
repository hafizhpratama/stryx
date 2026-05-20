//! `validation/class-validator` adapter — sanitiser patterns for the
//! decorator-based DTO validator NestJS ships with by default.
//!
//! `class-validator` decorates DTO class properties (`@IsString()`,
//! `@IsEmail()`, `@Min(0)`, …) and exposes a runtime entry point that
//! walks the decorators against an incoming object. Three entry points
//! are in common use:
//!
//! - `validate(dto)`         — async, returns an array of `ValidationError`
//!   objects. Empty array means valid.
//! - `validateOrReject(dto)` — async, throws on the first invalid field
//!   (canonical throw-on-fail shape).
//! - `validateSync(dto)`     — synchronous variant of `validate`.
//!
//! All three are equivalent to a `SchemaParse` from the engine's
//! perspective: the call inspects `dto` against a schema (the
//! decorator metadata on its class) and the surviving control-flow
//! branch carries a validated value. Adopting `SanitizerKind::SchemaParse`
//! keeps `class-validator` interchangeable with `zod`, `valibot`,
//! `joi`, etc. so the generic `flow/unvalidated-body-to-db` rule
//! treats them uniformly.
//!
//! ## Matcher shapes
//!
//! Each pattern carries **two** matchers to cover the realistic call
//! shapes in NestJS code:
//!
//! 1. `ImportedCall { module: "class-validator", name: "<fn>" }` —
//!    the precise case: `import { validate } from "class-validator";`
//!    followed by `validate(dto)`. This requires the project index to
//!    resolve the import, which production scans always have.
//! 2. `MethodCallAnyReceiver { method: "<fn>" }` — a relaxed fallback
//!    for shapes like `cv.validate(dto)` or `validators.validate(dto)`
//!    where a thin namespace wrapper sits between the import and the
//!    call site. The substrate's `ImportedCall` only fires on
//!    bare-ident callees, so without the fallback those wrapped shapes
//!    would slip through. The trade-off: any unrelated
//!    `.validate(...)` call in the project (e.g. a custom helper that
//!    happens to share the name) is also recognised as a sanitiser.
//!    On the sanitiser side this is the safe direction of error — a
//!    false-positive sanitisation produces a missed finding, never an
//!    inflated one (per ADR 0014's sanitiser-confidence policy).
//!
//! ## Hint identity
//!
//! Detection is wired in [`stryx_index::profile::detect`] under the
//! validator family; the corresponding `ValidatorHint::ClassValidator`
//! serialises as `"class-validator"`, which is what the default
//! `is_enabled` resolution compares the adapter ID suffix against.
//!
//! [ADR 0014]: ../../../docs/decisions/0014-adapter-substrate-api.md

use crate::adapters::{
    AdapterId, AdapterKind, AstMatcher, SanitiserPattern, SanitizerKind, StackAdapter,
};

pub struct ClassValidatorAdapter;

// =============================================================================
// Sanitiser patterns
// =============================================================================
//
// One pattern per entry-point function. The relaxed
// `MethodCallAnyReceiver` matcher is intentional — see the module-level
// note for the false-positive trade-off rationale.

static SANITISERS: &[SanitiserPattern] = &[
    // `validate(dto)` — async, returns `ValidationError[]`. The most
    // common shape in NestJS controller bodies that bypass
    // `ValidationPipe`.
    SanitiserPattern {
        id: "validation/class-validator/validate",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[
            AstMatcher::ImportedCall {
                module: "class-validator",
                name: "validate",
            },
            AstMatcher::MethodCallAnyReceiver { method: "validate" },
        ],
    },
    // `validateOrReject(dto)` — async throw-on-fail. The
    // `SchemaParse` semantic still fits: the call returns iff
    // validation passes, so any expression on the post-call path is
    // schema-validated.
    SanitiserPattern {
        id: "validation/class-validator/validate-or-reject",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[
            AstMatcher::ImportedCall {
                module: "class-validator",
                name: "validateOrReject",
            },
            AstMatcher::MethodCallAnyReceiver {
                method: "validateOrReject",
            },
        ],
    },
    // `validateSync(dto)` — sync variant of `validate`. Less common in
    // request handlers (handlers are typically async), but standard in
    // worker / job / CLI code paths.
    SanitiserPattern {
        id: "validation/class-validator/validate-sync",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[
            AstMatcher::ImportedCall {
                module: "class-validator",
                name: "validateSync",
            },
            AstMatcher::MethodCallAnyReceiver {
                method: "validateSync",
            },
        ],
    },
];

impl StackAdapter for ClassValidatorAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("validation/class-validator")
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
    fn class_validator_adapter_exposes_expected_sanitiser_patterns() {
        let sanitisers = ClassValidatorAdapter.sanitisers();
        // One pattern per entry-point function — see the SANITISERS
        // array for the ID-by-ID rationale.
        assert_eq!(sanitisers.len(), 3);
        let ids: Vec<&str> = sanitisers.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"validation/class-validator/validate"));
        assert!(ids.contains(&"validation/class-validator/validate-or-reject"));
        assert!(ids.contains(&"validation/class-validator/validate-sync"));

        // Every pattern must classify as SchemaParse — that's the
        // contract the generic `flow/unvalidated-body-to-db` rule
        // consults to clear UserInput taint.
        for s in sanitisers {
            assert_eq!(
                s.sanitizer,
                SanitizerKind::SchemaParse,
                "wrong SanitizerKind for {}",
                s.id
            );
            // Two matchers each (ImportedCall + MethodCallAnyReceiver).
            // Pin the count so a refactor that drops one shape is
            // caught here.
            assert_eq!(s.matchers.len(), 2, "wrong matcher count for {}", s.id);
        }
    }

    #[test]
    fn class_validator_adapter_is_validator_kind() {
        assert_eq!(
            ClassValidatorAdapter.id(),
            AdapterId("validation/class-validator")
        );
        assert_eq!(ClassValidatorAdapter.kind(), AdapterKind::Validator);
    }

    #[test]
    fn is_enabled_returns_true_under_class_validator_profile() {
        // `ValidatorHint::ClassValidator` at 0.90 is well above the
        // 0.60 enable floor — the default `is_enabled` resolution
        // must activate the adapter. The id-suffix matching relies on
        // `ValidatorHint::ClassValidator` serialising to
        // `"class-validator"` via the enum's kebab-case rule.
        let profile = ProjectProfile {
            validators: vec![Detected {
                id: ValidatorHint::ClassValidator,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(ClassValidatorAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_zod_profile() {
        // A profile that detected Zod but not class-validator — the
        // class-validator adapter must stay disabled. Guards against
        // the regression where the kind/name split lets a same-kind
        // sibling validator activate the adapter.
        let profile = ProjectProfile {
            validators: vec![Detected {
                id: ValidatorHint::Zod,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!ClassValidatorAdapter.is_enabled(&profile));
    }
}
