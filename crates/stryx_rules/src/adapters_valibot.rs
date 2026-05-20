//! `validation/valibot` adapter — sanitiser patterns for Valibot, the
//! tree-shakeable, smaller-bundle alternative to Zod.
//!
//! Valibot's runtime surface is shaped differently from Zod's. Where
//! Zod exposes parse on the schema object itself
//! (`UserSchema.parse(value)`), Valibot ships parsing as **top-level
//! functions** imported from the `valibot` package:
//!
//! ```ts
//! import { parse, safeParse } from "valibot";
//! const body = parse(UserSchema, await req.json());
//! ```
//!
//! Four entry points are in common use, mirroring Zod's sync/async ×
//! throw/result-object matrix so the engine can treat the two
//! validators uniformly:
//!
//! - `parse(schema, input)`           — sync, throws on invalid.
//! - `safeParse(schema, input)`       — sync, returns
//!   `{ success: true, output } | { success: false, issues }`. The
//!   call is only *truly* sanitising on the post-`success` branch;
//!   the adapter still classifies it as `SchemaParse` because that
//!   downstream control-flow check is a rule-level concern, not a
//!   pattern-recognition one (same contract Zod's `safeParse` uses).
//! - `parseAsync(schema, input)`      — async variant of `parse`,
//!   used when schemas contain async transforms / pipes.
//! - `safeParseAsync(schema, input)`  — async result-object variant.
//!
//! All four classify as [`SanitizerKind::SchemaParse`] so the generic
//! `flow/unvalidated-body-to-db` rule (and peers) consume Valibot,
//! Zod, class-validator, joi, etc. through one substrate.
//!
//! ## Matcher shape and false-positive trade-off
//!
//! Each pattern carries a single [`AstMatcher::ImportedCall`] matcher
//! keyed on `module: "valibot"` plus the entry-point function name.
//! This is the **strict** end of the matcher-shape spectrum: the
//! matcher only fires when the per-file import map records `parse`
//! (etc.) as imported directly from `"valibot"`.
//!
//! The deliberate trade-off versus the class-validator adapter's
//! relaxed shape (which adds a `MethodCallAnyReceiver` fallback):
//!
//! - **Why strict here.** Valibot's entry-point names — `parse`,
//!   `safeParse` — collide with extremely common platform calls
//!   (`JSON.parse`, `Date.parse`, `URL.parse`, `parseInt`-adjacent
//!   helpers, custom `RouteSpec.parse`). On the sanitiser side a
//!   spurious match is the **less-safe** direction: it clears taint
//!   that wasn't really sanitised and produces a missed finding. A
//!   `MethodCallAnyReceiver { method: "parse" }` fallback would
//!   absorb every `JSON.parse(await req.json())` call site as a
//!   Valibot parse — exactly the wrong cliff to fall off.
//! - **Why strict was tolerable for class-validator.** Its entry
//!   points (`validate`, `validateOrReject`, `validateSync`) are
//!   uncommon enough that the relaxed shape is broadly safe; plus
//!   `class-validator` is canonically used through a re-export
//!   namespace (`import * as cv from "class-validator"; cv.validate(dto)`)
//!   which only the relaxed shape catches.
//! - **Why strict isn't tolerable for Zod-style relaxation.** Zod
//!   accepts `MethodCallAnyReceiver { method: "parse" }` only because
//!   its activation is gated on a Zod-detected profile and its API
//!   surface is overwhelmingly the receiver-method shape; Valibot's
//!   API surface is overwhelmingly the imported-function shape, so
//!   the relaxed Zod-style matcher doesn't even cover the dominant
//!   Valibot call shape.
//!
//! The known cost of strictness: aliased imports slip through.
//! `import { parse as vparse } from "valibot"; vparse(schema, x)` is
//! a real codebase pattern (often used precisely to avoid the
//! `JSON.parse` name collision). With `ImportedCall { name: "parse" }`
//! we look up the bare-ident `vparse` in the import map and find no
//! entry — the matcher abstains. That is the bug-bargain we accept:
//! aliased imports are rare in practice, and a missed sanitiser
//! recognition produces an extra (likely true) finding rather than a
//! silently dropped one, which is the safer error direction on the
//! flow rules consuming `EnabledAdapters::sanitisers`.
//!
//! Mitigation later: a future substrate slice could add a
//! `MethodCallOnTypedReceiver` or an `AliasResolvingImportedCall`
//! matcher that walks the per-file aliases. The substrate doesn't
//! yet support either, and threading that resolution through the
//! hot path is a non-trivial change — out of scope here.
//!
//! ## Hint identity
//!
//! Detection lives in [`stryx_index::profile::detect`] under the
//! validator family; [`ValidatorHint::Valibot`] serialises as
//! `"valibot"` via the enum's `serde(rename_all = "kebab-case")`
//! rule, which is what the default `is_enabled` resolution in
//! [`crate::adapters`] compares the adapter ID suffix against.
//!
//! [ADR 0014]: ../../../docs/decisions/0014-adapter-substrate-api.md
//! [`ValidatorHint::Valibot`]: stryx_index::profile::ValidatorHint::Valibot

use crate::adapters::{
    AdapterId, AdapterKind, AstMatcher, SanitiserPattern, SanitizerKind, StackAdapter,
};

pub struct ValibotAdapter;

// =============================================================================
// Sanitiser patterns
// =============================================================================
//
// One pattern per top-level entry-point function. Each pattern carries
// a single `ImportedCall { module: "valibot", name: <fn> }` matcher —
// the strict shape that pins the call to a real `valibot` import (see
// the module-level note for the false-positive trade-off rationale).
//
// Pattern IDs mirror the `validation/zod/*` family so reporters can
// group multi-validator projects by suffix and dashboards comparing
// adapter coverage across validators line up segment-for-segment.

static SANITISERS: &[SanitiserPattern] = &[
    // `parse(schema, input)` — sync throw-on-fail, the canonical
    // entry point used in most route handlers:
    // `const body = parse(UserSchema, await req.json());`.
    SanitiserPattern {
        id: "validation/valibot/parse",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::ImportedCall {
            module: "valibot",
            name: "parse",
        }],
    },
    // `safeParse(schema, input)` — sync result-object form. The
    // adapter pattern fires on the call itself; the downstream
    // `if (result.success)` gate is the rule's job to require.
    SanitiserPattern {
        id: "validation/valibot/safe-parse",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::ImportedCall {
            module: "valibot",
            name: "safeParse",
        }],
    },
    // `parseAsync(schema, input)` — async throw-on-fail. Used when
    // schemas include async pipes / transforms.
    SanitiserPattern {
        id: "validation/valibot/parse-async",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::ImportedCall {
            module: "valibot",
            name: "parseAsync",
        }],
    },
    // `safeParseAsync(schema, input)` — async result-object form.
    SanitiserPattern {
        id: "validation/valibot/safe-parse-async",
        sanitizer: SanitizerKind::SchemaParse,
        matchers: &[AstMatcher::ImportedCall {
            module: "valibot",
            name: "safeParseAsync",
        }],
    },
];

impl StackAdapter for ValibotAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("validation/valibot")
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
    fn valibot_adapter_exposes_expected_sanitiser_patterns() {
        let sanitisers = ValibotAdapter.sanitisers();
        // One pattern per Valibot top-level entry-point function. The
        // four-pattern surface mirrors `validation/zod/*` so a project
        // with both validators surfaces a symmetric adapter view.
        assert_eq!(sanitisers.len(), 4);
        let ids: Vec<&str> = sanitisers.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"validation/valibot/parse"));
        assert!(ids.contains(&"validation/valibot/safe-parse"));
        assert!(ids.contains(&"validation/valibot/parse-async"));
        assert!(ids.contains(&"validation/valibot/safe-parse-async"));

        // Every pattern must classify as SchemaParse — that's the
        // contract the generic `flow/unvalidated-body-to-db` rule
        // consults to clear UserInput taint, and what makes Valibot
        // interchangeable with Zod / class-validator / joi.
        for s in sanitisers {
            assert_eq!(
                s.sanitizer,
                SanitizerKind::SchemaParse,
                "wrong SanitizerKind for {}",
                s.id
            );
            // Single `ImportedCall` matcher per pattern. Pin the count
            // so a future refactor that loosens to add a
            // `MethodCallAnyReceiver` fallback (which would create the
            // `JSON.parse` false-sanitiser regression called out in
            // the module-level docs) is caught here.
            assert_eq!(s.matchers.len(), 1, "wrong matcher count for {}", s.id);
            // Each matcher must be the strict `ImportedCall` shape
            // anchored to the `valibot` module. Pattern-match rather
            // than equality-test so a future expansion that adds
            // alternate matchers on the same pattern still surfaces a
            // descriptive failure here.
            match s.matchers[0] {
                AstMatcher::ImportedCall { module, .. } => {
                    assert_eq!(
                        module, "valibot",
                        "matcher for {} must be anchored to the valibot module",
                        s.id
                    );
                }
                other => panic!("matcher for {} must be ImportedCall, got {:?}", s.id, other),
            }
        }
    }

    #[test]
    fn valibot_adapter_is_validator_kind() {
        assert_eq!(ValibotAdapter.id(), AdapterId("validation/valibot"));
        assert_eq!(ValibotAdapter.kind(), AdapterKind::Validator);
    }

    #[test]
    fn is_enabled_returns_true_under_valibot_profile() {
        // `ValidatorHint::Valibot` at 0.90 is well above the 0.60
        // enable floor — the default `is_enabled` resolution must
        // activate the adapter. The id-suffix matching relies on
        // `ValidatorHint::Valibot` serialising to `"valibot"` via the
        // enum's kebab-case rule.
        let profile = ProjectProfile {
            validators: vec![Detected {
                id: ValidatorHint::Valibot,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(ValibotAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_zod_profile() {
        // A profile that detected Zod but not Valibot — the Valibot
        // adapter must stay disabled. Guards against the regression
        // where the kind/name split lets a same-kind sibling
        // validator activate the adapter (the mirror of the Zod
        // adapter's own valibot-profile negative test).
        let profile = ProjectProfile {
            validators: vec![Detected {
                id: ValidatorHint::Zod,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!ValibotAdapter.is_enabled(&profile));
    }
}
