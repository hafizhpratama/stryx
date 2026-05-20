//! `auth/better-auth` adapter — Better Auth session-validation patterns.
//!
//! Better Auth is a TypeScript-first authentication library that has
//! gained traction in modern Bun + Hono + Drizzle stacks. Unlike
//! NextAuth/Auth.js (which exposes `getServerSession`) or Lucia (which
//! exposes `lucia.validateRequest`), Better Auth gates session
//! validation through a single namespaced surface:
//!
//! ```ts
//! const session = await auth.api.getSession({ headers: req.headers });
//! if (!session) return new Response("Unauthorized", { status: 401 });
//! ```
//!
//! The `auth` binding is the configured Better Auth instance; `.api`
//! is the server-side method namespace; `.getSession(...)` validates
//! the cookie/header-bound session and returns `null` on failure.
//! That single call shape is the load-bearing signal — if a wrapper
//! contains it, the wrapper enforces auth; if a handler runs
//! downstream of it (with the null-return check in place), the
//! handler runs only for authenticated sessions.
//!
//! ## Sanitiser patterns
//!
//! Better Auth's session-validation call clears `UserInput` taint on
//! the path past a successful (`session !== null`) check, identical
//! to the `SanitizerKind::AuthCheck` contract used for
//! `getServerSession`, `lucia.validateRequest`, and the rest of the
//! inline list in [`crate::steps::sanitizers::auth::AUTH_HELPER_NAMES`].
//!
//! Three pattern IDs are exposed even though the matcher set is
//! deliberately narrow:
//!
//!   - `auth/better-auth/get-session` — primary recognition of
//!     `<any>.getSession(...)` via [`AstMatcher::MethodCallAnyReceiver`].
//!     This is the broadest matcher; it fires on
//!     `auth.api.getSession(...)`, `betterAuth.api.getSession(...)`,
//!     or any aliased binding the user adopted. The method name itself
//!     is already on the inline `AUTH_HELPER_NAMES` list, so adopting
//!     the matcher here keeps adapter output shape-equivalent to the
//!     inline recogniser without re-deriving the receiver.
//!   - `auth/better-auth/api-get-session` — narrower recognition of
//!     the canonical Better Auth chain `auth.api.getSession(...)`.
//!     Scoped via [`AstMatcher::MethodCall`] with the literal `auth.api`
//!     receiver so reports can distinguish "matched the canonical
//!     Better Auth shape" from "matched a generic `getSession` call".
//!   - `auth/better-auth/session-from-cookie` — also targets
//!     `auth.api.getSession`, but is exposed as a separate pattern ID
//!     to give the reporter a dedicated bucket for the
//!     `{ headers: req.headers }` cookie-bound call, which is the
//!     Better Auth idiom in the official docs. The matcher itself
//!     is the same `auth.api.getSession` chain — argument-shape
//!     recognition lives at the rule level, where it can inspect
//!     the `headers:` property; the adapter layer only commits to
//!     the call-site shape per the substrate's syntactic remit.
//!
//! ## Guard patterns
//!
//! [`GuardKind::SessionRequired`] declares "the analyzer recognises
//! this call as a session-required gate; the rule decides whether the
//! surrounding control flow actually enforces it". The matcher list
//! is the same `getSession` shapes as the sanitiser patterns — the
//! split is semantic: a sanitiser clears taint on the post-call value,
//! a guard marks the call site as a candidate for early-return
//! analysis in [`crate::flows::auth_bypass_via_wrapper`]. The actual
//! return-on-null control-flow check stays in the rule; the adapter
//! only contributes "this call counts as a session check".
//!
//! ## Activation
//!
//! Default `is_enabled` — active when the project profile contains an
//! `AuthHint::BetterAuth` entry at confidence ≥
//! [`crate::adapters::ENABLE_CONFIDENCE_FLOOR`] (`0.60`). The profile
//! crate serialises `BetterAuth` as `"better-auth"`, which matches the
//! `better-auth` suffix in this adapter's `auth/better-auth` ID. A
//! project on Auth.js (`AuthHint::AuthJs`, serialised as `"auth-js"`)
//! must not activate this adapter even at high confidence — adapter
//! activation is per-name, not per-kind.

use crate::adapters::{
    AdapterId, AdapterKind, AstMatcher, GuardKind, GuardPattern, SanitiserPattern, SanitizerKind,
    StackAdapter,
};

pub struct BetterAuthAdapter;

// =============================================================================
// Sanitiser patterns — `auth.api.getSession(...)` and aliases
// =============================================================================
//
// All three patterns recognise the same family of calls; the IDs exist
// so the reporter can group findings by Better Auth call shape rather
// than by raw method name. The matchers themselves are constructed to
// keep the broadest matcher (`MethodCallAnyReceiver`) at one end and
// the narrowest (`auth.api.getSession`) at the other — rules consult
// pattern IDs, so a finding tagged `api-get-session` carries strictly
// more context than one tagged `get-session`.

static SANITISERS: &[SanitiserPattern] = &[
    // Broadest: any receiver, `getSession` method. Catches aliased
    // bindings (`betterAuth.api.getSession`,
    // `serverAuth.api.getSession`) without the adapter needing to
    // enumerate every project's import-rename convention.
    SanitiserPattern {
        id: "auth/better-auth/get-session",
        sanitizer: SanitizerKind::AuthCheck,
        matchers: &[AstMatcher::MethodCallAnyReceiver {
            method: "getSession",
        }],
    },
    // Narrower: canonical `auth.api.getSession(...)` chain. Same
    // method, but the dotted-receiver matcher anchors it to the
    // documented Better Auth shape. Both patterns fire on the
    // canonical call — the broader one supplies the generic
    // recognition, this one supplies the "definitely Better Auth"
    // attribution.
    SanitiserPattern {
        id: "auth/better-auth/api-get-session",
        sanitizer: SanitizerKind::AuthCheck,
        matchers: &[AstMatcher::MethodCall {
            receiver: "auth.api",
            method: "getSession",
        }],
    },
    // Same call shape; separate ID so the reporter can bucket the
    // cookie/header-bound Better Auth idiom distinctly. Argument-shape
    // recognition (`{ headers: req.headers }`) lives at the rule
    // level — the adapter substrate commits to call-site shape only.
    SanitiserPattern {
        id: "auth/better-auth/session-from-cookie",
        sanitizer: SanitizerKind::AuthCheck,
        matchers: &[AstMatcher::MethodCall {
            receiver: "auth.api",
            method: "getSession",
        }],
    },
];

// =============================================================================
// Guard patterns — control-flow gates on session validation
// =============================================================================
//
// `SessionRequired` declares "if this call appears in a wrapper, the
// wrapper is plausibly a session-required gate". The actual
// return-on-null analysis lives in `flow/auth-bypass-via-wrapper`;
// this pattern just signals candidacy. Matcher list mirrors the
// sanitiser side so the same call recognised as a value-level
// sanitiser also registers as a control-flow guard candidate.

static GUARDS: &[GuardPattern] = &[GuardPattern {
    id: "auth/better-auth/session-required",
    guard: GuardKind::SessionRequired,
    matchers: &[
        AstMatcher::MethodCallAnyReceiver {
            method: "getSession",
        },
        AstMatcher::MethodCall {
            receiver: "auth.api",
            method: "getSession",
        },
    ],
}];

impl StackAdapter for BetterAuthAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("auth/better-auth")
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
    fn better_auth_adapter_exposes_expected_sanitiser_patterns() {
        let sanitisers = BetterAuthAdapter.sanitisers();
        assert_eq!(sanitisers.len(), 3);
        let ids: Vec<&str> = sanitisers.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"auth/better-auth/get-session"));
        assert!(ids.contains(&"auth/better-auth/api-get-session"));
        assert!(ids.contains(&"auth/better-auth/session-from-cookie"));

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
    fn better_auth_adapter_exposes_expected_guard_patterns() {
        let guards = BetterAuthAdapter.guards();
        assert_eq!(guards.len(), 1);
        assert_eq!(guards[0].id, "auth/better-auth/session-required");
        assert_eq!(guards[0].guard, GuardKind::SessionRequired);
    }

    #[test]
    fn better_auth_adapter_is_auth_kind() {
        assert_eq!(BetterAuthAdapter.kind(), AdapterKind::Auth);
        assert_eq!(BetterAuthAdapter.id(), AdapterId("auth/better-auth"));
    }

    #[test]
    fn is_enabled_returns_true_under_better_auth_profile() {
        // High-confidence Better Auth detection in the profile must
        // activate the adapter via the default `is_enabled` path
        // (matches `auth/<name>` adapter ID suffix against the
        // `AuthHint::BetterAuth` serde spelling `"better-auth"`).
        let profile = ProjectProfile {
            auth_layers: vec![Detected {
                id: AuthHint::BetterAuth,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(BetterAuthAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_auth_js_profile() {
        // An Auth.js-only profile must not activate the Better Auth
        // adapter, even at high confidence — adapter activation is
        // per-name, not per-kind.
        let profile = ProjectProfile {
            auth_layers: vec![Detected {
                id: AuthHint::AuthJs,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!BetterAuthAdapter.is_enabled(&profile));
    }
}
