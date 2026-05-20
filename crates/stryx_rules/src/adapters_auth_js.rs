//! `auth/auth-js` adapter — Auth.js / NextAuth session-validation patterns.
//!
//! Auth.js (the v5 rename of NextAuth.js) is the most widely deployed
//! authentication library for Next.js. It exposes session validation
//! through two distinct call shapes depending on major version:
//!
//! ```ts
//! // Legacy NextAuth v4: bare-ident, imported from "next-auth".
//! import { getServerSession } from "next-auth";
//! const session = await getServerSession(authOptions);
//! if (!session) return new Response("Unauthorized", { status: 401 });
//!
//! // Auth.js v5: project-local re-export, bare-ident call.
//! //   // auth.ts
//! //   export const { auth } = NextAuth({ providers: [...] });
//! import { auth } from "@/auth";
//! const session = await auth();
//! if (!session?.user) redirect("/signin");
//! ```
//!
//! Auth.js also exposes `.getSession(...)` in adjacent client/server
//! helpers (e.g. `next-auth/react`'s `getSession`, the `@auth/*` core
//! `getSession` accessor). The method-name shape is shared with
//! Better Auth's `auth.api.getSession(...)` idiom — the overlap is
//! deliberate, and the sanitiser-side false positive is a *missed*
//! finding, not an inflated one (a recognised auth check that doesn't
//! actually gate is a soundness loss for the auth-bypass rule, but
//! adapter recognition only enables candidacy; the rule layer decides
//! whether the surrounding control flow enforces the gate).
//!
//! ## Sanitiser patterns
//!
//! Three pattern IDs cover the three syntactic shapes Auth.js exposes:
//!
//!   - `auth/auth-js/get-server-session` — `getServerSession(...)`
//!     imported from `"next-auth"`. Scoped via
//!     [`AstMatcher::ImportedCall`] so a local helper literally named
//!     `getServerSession` (re-exported, wrapped, or simply named the
//!     same) does not falsely register as Auth.js. This is the v4
//!     idiom; still widely deployed on long-lived NextAuth codebases.
//!   - `auth/auth-js/auth` — the v5 idiomatic `auth()` call. Two
//!     matchers fire in parallel:
//!       * [`AstMatcher::ImportedCall`] anchored on
//!         `module: "@auth/core"` for projects that import directly
//!         from the framework core package.
//!       * [`AstMatcher::MethodCallAnyReceiver`] on `method: "auth"`
//!         to cover namespace-style invocations
//!         (`authConfig.auth(req)`, `nextAuth.auth()`, etc.) where
//!         the binding is reached through a member expression.
//!
//!     The project-local re-export shape — `import { auth } from "@/auth"`
//!     then `auth()` — is *not* covered by either matcher (the
//!     `ImportedCall` module specifier won't match the user-controlled
//!     re-export path, and a bare-ident call isn't a `MethodCall`).
//!     The inline [`AUTH_HELPER_NAMES`] recogniser in
//!     [`crate::steps::sanitizers::auth`] still catches the bare name
//!     `auth` until that path migrates to the adapter substrate; the
//!     soundness story is unchanged for v5 users on the current rule
//!     codebase.
//!   - `auth/auth-js/get-session` — `.getSession(...)` method on any
//!     receiver. The matcher is intentionally broad
//!     ([`AstMatcher::MethodCallAnyReceiver`]) — Auth.js documentation
//!     and ecosystem code call this through several aliased bindings
//!     (`nextAuth.getSession`, `authClient.getSession`,
//!     `session.getSession`). The same shape also matches Better
//!     Auth's `auth.api.getSession(...)` — both adapters contribute
//!     overlapping patterns by design, and rules consume the union.
//!
//! ## Guard patterns
//!
//! [`GuardKind::SessionRequired`] declares "if this call appears in a
//! wrapper, the wrapper is plausibly a session-required gate". The
//! matcher list mirrors the sanitiser side so the same call recognised
//! as a value-level sanitiser also registers as a control-flow guard
//! candidate. Actual return-on-null analysis lives in
//! [`crate::flows::auth_bypass_via_wrapper`]; the adapter only
//! contributes "this call counts as a session check".
//!
//! ## Activation
//!
//! Default `is_enabled` — active when the project profile contains an
//! `AuthHint::AuthJs` entry at confidence ≥
//! [`crate::adapters::ENABLE_CONFIDENCE_FLOOR`] (`0.60`). The profile
//! crate serialises `AuthJs` as `"auth-js"`, which matches the
//! `auth-js` suffix in this adapter's `auth/auth-js` ID. A Better
//! Auth-only profile (`AuthHint::BetterAuth`, serialised as
//! `"better-auth"`) must not activate this adapter even at high
//! confidence — adapter activation is per-name, not per-kind.
//!
//! [`AUTH_HELPER_NAMES`]: crate::steps::sanitizers::AUTH_HELPER_NAMES

use crate::adapters::{
    AdapterId, AdapterKind, AstMatcher, GuardKind, GuardPattern, SanitiserPattern, SanitizerKind,
    StackAdapter,
};

pub struct AuthJsAdapter;

// =============================================================================
// Sanitiser patterns — `getServerSession`, `auth()`, `.getSession(...)`
// =============================================================================
//
// Pattern IDs are stable: reporters group findings by ID, and the
// `get-server-session` / `auth` / `get-session` split tells consumers
// which Auth.js call shape the analyser saw. All three clear taint as
// `SanitizerKind::AuthCheck`; the semantic claim is identical.

static SANITISERS: &[SanitiserPattern] = &[
    // Legacy NextAuth v4: `import { getServerSession } from "next-auth"`
    // followed by a bare-ident call. `ImportedCall` is the right shape
    // here — the function name alone is too generic to anchor on, and
    // the module-specifier check is what distinguishes a real NextAuth
    // call from a same-named local helper.
    SanitiserPattern {
        id: "auth/auth-js/get-server-session",
        sanitizer: SanitizerKind::AuthCheck,
        matchers: &[AstMatcher::ImportedCall {
            module: "next-auth",
            name: "getServerSession",
        }],
    },
    // Auth.js v5: the idiomatic `auth()` call. Two matchers fire in
    // parallel so both the direct-`@auth/core`-import shape and the
    // namespace-method shape (`<binding>.auth(...)`) register. The
    // project-local re-export case (`import { auth } from "@/auth"`)
    // is intentionally not covered at adapter level — see module
    // doc comment for the soundness analysis.
    SanitiserPattern {
        id: "auth/auth-js/auth",
        sanitizer: SanitizerKind::AuthCheck,
        matchers: &[
            AstMatcher::ImportedCall {
                module: "@auth/core",
                name: "auth",
            },
            AstMatcher::MethodCallAnyReceiver { method: "auth" },
        ],
    },
    // `.getSession(...)` on any receiver. Overlaps Better Auth's
    // matcher by design; both adapters can be enabled in the same
    // project (an Auth.js → Better Auth migration in progress) and
    // the union of patterns is what rules consume.
    SanitiserPattern {
        id: "auth/auth-js/get-session",
        sanitizer: SanitizerKind::AuthCheck,
        matchers: &[AstMatcher::MethodCallAnyReceiver {
            method: "getSession",
        }],
    },
];

// =============================================================================
// Guard patterns — control-flow gates on session validation
// =============================================================================
//
// Single guard pattern; matcher list mirrors the sanitiser side. The
// rule layer (`flow/auth-bypass-via-wrapper`) decides whether the
// surrounding wrapper enforces the gate (early return on null,
// throws, etc.); the adapter only contributes "this call counts as
// a session check".

static GUARDS: &[GuardPattern] = &[GuardPattern {
    id: "auth/auth-js/session-required",
    guard: GuardKind::SessionRequired,
    matchers: &[
        AstMatcher::ImportedCall {
            module: "next-auth",
            name: "getServerSession",
        },
        AstMatcher::ImportedCall {
            module: "@auth/core",
            name: "auth",
        },
        AstMatcher::MethodCallAnyReceiver { method: "auth" },
        AstMatcher::MethodCallAnyReceiver {
            method: "getSession",
        },
    ],
}];

impl StackAdapter for AuthJsAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("auth/auth-js")
    }
    fn kind(&self) -> AdapterKind {
        AdapterKind::Auth
    }
    fn sanitisers(&self) -> &'static [SanitiserPattern] {
        SANITISERS
    }
    fn guards(&self) -> &'static [GuardPattern] {
        GUARDS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stryx_index::profile::{AuthHint, Detected, ProjectProfile};

    #[test]
    fn auth_js_adapter_exposes_expected_sanitiser_patterns() {
        let sanitisers = AuthJsAdapter.sanitisers();
        assert_eq!(sanitisers.len(), 3);
        let ids: Vec<&str> = sanitisers.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"auth/auth-js/get-server-session"));
        assert!(ids.contains(&"auth/auth-js/auth"));
        assert!(ids.contains(&"auth/auth-js/get-session"));

        // All three patterns clear taint as `AuthCheck` — the
        // `SanitizerKind::AuthCheck` contract is the load-bearing
        // semantic claim, regardless of which call shape matched.
        for pattern in sanitisers {
            assert_eq!(
                pattern.sanitizer,
                SanitizerKind::AuthCheck,
                "sanitizer kind mismatch on {}",
                pattern.id
            );
        }
    }

    #[test]
    fn auth_js_adapter_exposes_expected_guard_patterns() {
        let guards = AuthJsAdapter.guards();
        assert_eq!(guards.len(), 1);
        assert_eq!(guards[0].id, "auth/auth-js/session-required");
        assert_eq!(guards[0].guard, GuardKind::SessionRequired);
    }

    #[test]
    fn auth_js_adapter_is_auth_kind() {
        assert_eq!(AuthJsAdapter.kind(), AdapterKind::Auth);
        assert_eq!(AuthJsAdapter.id(), AdapterId("auth/auth-js"));
    }

    #[test]
    fn is_enabled_returns_true_under_auth_js_profile() {
        // High-confidence Auth.js detection in the profile must
        // activate the adapter via the default `is_enabled` path
        // (matches `auth/<name>` adapter ID suffix against the
        // `AuthHint::AuthJs` serde spelling `"auth-js"`).
        let profile = ProjectProfile {
            auth_layers: vec![Detected {
                id: AuthHint::AuthJs,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(AuthJsAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_better_auth_profile() {
        // A Better Auth-only profile must not activate the Auth.js
        // adapter, even at high confidence — adapter activation is
        // per-name, not per-kind. The mirror of Better Auth's
        // "auth-js doesn't enable us" test on this side.
        let profile = ProjectProfile {
            auth_layers: vec![Detected {
                id: AuthHint::BetterAuth,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!AuthJsAdapter.is_enabled(&profile));
    }
}
