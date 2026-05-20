//! `validation/ajv` adapter — sanitiser patterns for Ajv, the fastest
//! JSON-Schema validator in the JavaScript ecosystem and the substrate
//! a large chunk of OpenAPI-driven backends use to validate request
//! bodies. Ajv is especially common in two stacks:
//!
//! - High-throughput Node/Fastify/Bun services where `parse`-style
//!   validators are too slow and `Ajv` is paired with `JSON.stringify`
//!   schemas for end-to-end validation.
//! - Tooling that auto-generates validators from an OpenAPI/JSON-Schema
//!   document (`fastify`, `oazapfts`, `openapi-typescript-codegen`,
//!   `swagger-jsdoc`-driven middleware) where the compiled validator
//!   is hidden behind a generated wrapper.
//!
//! Ajv's runtime surface centres on three syntactic shapes:
//!
//! - `ajv.validate(schema, data)` — top-level instance method.
//!   `import Ajv from "ajv"; const ajv = new Ajv(); ajv.validate(schema, data)`.
//!   Returns a boolean; the post-`true` branch carries a validated value.
//!   The two-arg form also accepts a pre-registered `schemaName` instead
//!   of an inline schema — same call shape, same boolean return, same
//!   sanitiser treatment.
//! - `ajv.validateSchema(schema)` — validates a schema document itself
//!   against the JSON-Schema meta-schema. Not strictly an input
//!   sanitiser, but it shares the `validate*` family naming and is the
//!   complementary call most schema-loading code reaches for; modelling
//!   it as `SchemaParse` mirrors how the other validator adapters
//!   classify their schema-validation entry points.
//! - `const validate = ajv.compile(schema); validate(data)` — the
//!   compiled-validator pattern. `compile` returns a bare function which
//!   is then invoked by its user-chosen local name. This is the canonical
//!   Ajv shape in high-throughput code and in generated wrappers, but it
//!   is **not recognised** by this adapter — see the deliberate-miss
//!   note below.
//!
//! From the engine's perspective each recognised call is a
//! [`SanitizerKind::SchemaParse`]: the call inspects an input against a
//! schema and the surviving control-flow branch carries a validated
//! value. Modelling all entries uniformly keeps Ajv interchangeable with
//! `zod`, `valibot`, `joi`, `yup`, and `class-validator` so the generic
//! `flow/unvalidated-body-to-db` rule treats them the same way.
//!
//! ## Matcher shape and false-positive trade-off
//!
//! Each pattern carries a single matcher:
//! [`AstMatcher::MethodCallAnyReceiver`] keyed on the method name. The
//! receiver's identity isn't tracked at the AST level — `ajv.validate`,
//! `validator.validate`, and `someThing.validate` all reduce to the
//! same method-name signal.
//!
//! `validate` is a deliberately broad name (`fastify`, `class-validator`,
//! `joi`, custom helpers all expose `.validate(...)`). On the sanitiser
//! side this is the **less-safe** direction — a spurious match clears
//! taint that wasn't really sanitised, producing a *missed* finding
//! rather than an inflated one. The class-validator and joi adapters
//! make the same trade-off with the same `.validate` shape; the three
//! coexist because profile-gating ensures the relevant adapter activates
//! only when project evidence points at that library.
//!
//! Mitigation today: this adapter activates only when the project
//! profile has surfaced a [`ValidatorHint::Ajv`] entry at or above the
//! enable floor. The activation itself is the project-level evidence
//! that `.validate(...)` is far more likely to be an Ajv call than an
//! unrelated helper. Outside Ajv projects the patterns simply don't
//! fire.
//!
//! Mitigation later: a future slice can introduce a more constrained
//! matcher (e.g. `MethodCallOnTypedReceiver`) that consults the per-file
//! import map for a receiver whose ultimate origin is `new Ajv(...)`.
//! The substrate doesn't yet support that, and threading receiver-type
//! tracking through the hot path is a non-trivial change — out of scope
//! here.
//!
//! ## Deliberate miss: compiled validators
//!
//! Ajv's hot-path API is `const validate = ajv.compile(schema);` followed
//! by bare-name `validate(data)` calls — the compiled validator is a
//! user-named local function, not a member call. Neither
//! [`AstMatcher::MethodCallAnyReceiver`] nor any existing matcher
//! variant recognises that shape: it's a bare-ident call whose callee
//! identity is only knowable through local data-flow ("which call
//! produced this binding?"), which the substrate doesn't model.
//!
//! Consequence: code shaped like
//! ```js
//! const validate = ajv.compile(schema);
//! if (validate(body)) { db.users.create({ data: body }); }
//! ```
//! is an accepted miss for this adapter. The inline path in
//! `flow/unvalidated-body-to-db` may still catch it via its
//! `validate*`/`verify*`/`check*`/`assert*` callee-name prefix heuristic
//! when the local happens to be named `validate*`, but that's
//! coincidental and not guaranteed by this adapter's contract.
//!
//! A future slice can add a `CompiledFromCall { source_method: "compile" }`
//! matcher type that walks the per-file binding map for `const X = Y.compile(...)`
//! shapes and recognises subsequent bare-name `X(...)` calls. The
//! substrate-level change touches the matcher enum, the matcher impl,
//! and the registry consumer; deferring it keeps this slice scoped to a
//! single new file.
//!
//! ## Hint identity
//!
//! Detection lives in [`stryx_index::profile::detect`] under the
//! validator family; [`ValidatorHint::Ajv`] serialises as `"ajv"` via
//! the enum's `serde(rename_all = "kebab-case")` rule, which is what
//! the default `is_enabled` resolution in [`crate::adapters`] compares
//! the adapter ID suffix against.
//!
//! [ADR 0014]: ../../../docs/decisions/0014-adapter-substrate-api.md
//! [`ValidatorHint::Ajv`]: stryx_index::profile::ValidatorHint::Ajv

use crate::adapters::{
    AdapterId, AdapterKind, AstMatcher, SanitiserPattern, SanitizerKind, StackAdapter,
};

pub struct AjvAdapter;

// =============================================================================
// Sanitiser patterns
// =============================================================================
//
// One pattern per Ajv entry-point method recognisable at AST-shape level.
// Each uses `MethodCallAnyReceiver` because the receiver's identity is
// opaque at AST-shape level — `ajv.validate`, `validator.validate`, and
// a hand-rolled `MySchema.validate` all reduce to the same method-name
// signal (see the module-level note on the false-positive trade-off).
//
// The compiled-validator shape (`const v = ajv.compile(s); v(data)`) is
// intentionally absent — see the deliberate-miss section in the module
// docs for why and what a future fix would look like.

static SANITISERS: &[SanitiserPattern] = &[
    // `ajv.validate(schema, data)` — the top-level Ajv instance method.
    // Receiver identity is opaque; the `validate` method name is the
    // signal. Also catches the `ajv.validate(schemaName, data)` shape
    // (pre-registered schemas) since the AST shape is identical.
    // Trade-off documented at module level: collides with Joi's
    // `schema.validate`, class-validator's `.validate(dto)`, and any
    // user-defined `.validate(...)` helper. Profile-gating keeps the
    // false-clear risk bounded to Ajv projects.
    SanitiserPattern {
        id: "validation/ajv/validate",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::MethodCallAnyReceiver { method: "validate" }],
    },
    // `ajv.validateSchema(schema)` — meta-validates a schema document.
    // Less common in request-handling paths than `validate`, but it's
    // the complementary entry point most schema-loading code reaches
    // for; modelling it as `SchemaParse` mirrors how the other
    // validator adapters classify their schema-validation entries.
    SanitiserPattern {
        id: "validation/ajv/validate-schema",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::MethodCallAnyReceiver {
            method: "validateSchema",
        }],
    },
];

impl StackAdapter for AjvAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("validation/ajv")
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
    fn ajv_adapter_exposes_expected_sanitiser_patterns() {
        let sanitisers = AjvAdapter.sanitisers();
        // Two patterns: `ajv.validate` and `ajv.validateSchema`. The
        // compiled-validator shape (`const v = ajv.compile(s); v(data)`)
        // is deliberately absent — see the module-level deliberate-miss
        // note. Pinning the count guards against accidental additions
        // (e.g. someone adding a bare `MethodCallAnyReceiver { "compile" }`,
        // which would clear taint on the *schema*, not the data, and
        // produce silent false-clears across every Ajv project).
        assert_eq!(sanitisers.len(), 2);
        let ids: Vec<&str> = sanitisers.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"validation/ajv/validate"));
        assert!(ids.contains(&"validation/ajv/validate-schema"));

        // Every pattern must classify as SchemaParse — that's the
        // contract the generic `flow/unvalidated-body-to-db` rule
        // consults to clear UserInput taint, and what makes Ajv
        // interchangeable with zod / class-validator / valibot / joi /
        // yup.
        for s in sanitisers {
            assert_eq!(
                s.sanitizer,
                SanitizerKind::SchemaParse,
                "wrong SanitizerKind for {}",
                s.id
            );
            // Single matcher per pattern — `MethodCallAnyReceiver`
            // keyed on the Ajv method name. Pin the count so a refactor
            // that adds an `ImportedCall` or `NamespaceCall` shape (Ajv
            // doesn't expose top-level validation functions; everything
            // hangs off an `Ajv` instance) is caught here.
            assert_eq!(s.matchers.len(), 1, "wrong matcher count for {}", s.id);
        }
    }

    #[test]
    fn ajv_adapter_is_validator_kind() {
        assert_eq!(AjvAdapter.id(), AdapterId("validation/ajv"));
        assert_eq!(AjvAdapter.kind(), AdapterKind::Validator);
    }

    #[test]
    fn is_enabled_returns_true_under_ajv_profile() {
        // `ValidatorHint::Ajv` at 0.90 is well above the 0.60 enable
        // floor — the default `is_enabled` resolution must activate
        // the adapter. The id-suffix matching relies on
        // `ValidatorHint::Ajv` serialising to `"ajv"` via the enum's
        // kebab-case rule.
        let profile = ProjectProfile {
            validators: vec![Detected {
                id: ValidatorHint::Ajv,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(AjvAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_zod_profile() {
        // A profile that detected Zod but not Ajv — the Ajv adapter
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
        assert!(!AjvAdapter.is_enabled(&profile));
    }
}
