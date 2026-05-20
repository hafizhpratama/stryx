//! `auth/clerk` adapter — Clerk session-validation patterns.
//!
//! Clerk is a hosted authentication service with first-class Next.js
//! integration. Server-side code authenticates a request through one of
//! two helper calls imported from the framework-specific entry point:
//!
//! ```ts
//! // App Router (recommended): `auth()` returns `{ userId, sessionId, ... }`
//! //                            or `null` for unauthenticated requests.
//! import { auth } from "@clerk/nextjs/server";
//! const { userId } = await auth();
//! if (!userId) return new Response("Unauthorized", { status: 401 });
//!
//! // App Router: `currentUser()` returns the full User object or `null`.
//! import { currentUser } from "@clerk/nextjs/server";
//! const user = await currentUser();
//! if (!user) redirect("/sign-in");
//!
//! // Legacy / Pages Router entry point — same names, different module
//! // specifier. Both shapes still appear in production code.
//! import { auth, currentUser } from "@clerk/nextjs";
//! ```
//!
//! Both calls return `null`-or-truthy in the same shape as Auth.js /
//! Better Auth — that null-return check is what the
//! `flow/auth-bypass-via-wrapper` rule consumes to decide whether a
//! wrapper enforces the gate. The adapter only commits to "this
//! call counts as a session check"; the surrounding control-flow
//! analysis lives in the rule layer.
//!
//! ## Disambiguation from `auth/auth-js`
//!
//! Auth.js's `auth/auth-js/auth` pattern recognises `auth()` imported
//! from `@auth/core`. Clerk's `auth/clerk/auth` pattern recognises
//! `auth()` imported from `@clerk/nextjs/server` or `@clerk/nextjs`.
//! The function names collide intentionally — both libraries
//! standardise on the same idiomatic name — and the
//! [`AstMatcher::ImportedCall`] module specifier is what tells them
//! apart. A project that imports `auth` from `"@/auth"` (a local
//! re-export) is covered by neither adapter; that shape continues to
//! be caught by the inline [`AUTH_HELPER_NAMES`] recogniser in
//! [`crate::steps::sanitizers::auth`] until that path migrates to the
//! adapter substrate.
//!
//! The same disambiguation applies to `currentUser()` — Clerk owns
//! the documented name on its two module specifiers; a local helper
//! literally named `currentUser` imported from elsewhere does not
//! register as Clerk.
//!
//! ## Sanitiser patterns
//!
//! Two pattern IDs cover the two Clerk-documented call shapes:
//!
//!   - `auth/clerk/auth` — `auth()` imported from
//!     `@clerk/nextjs/server` (App Router) or `@clerk/nextjs` (legacy
//!     / pages). Both module specifiers are documented entry points
//!     and still appear in production code; both matchers fire so
//!     either import style is recognised.
//!   - `auth/clerk/current-user` — `currentUser()` imported from the
//!     same two module specifiers. Same dual-matcher rationale.
//!
//! Backend-SDK calls (`clerk.users.getUser(userId)`) are *not* covered
//! at adapter level. Those calls take a user ID as input and return a
//! `User` record; they are not session-validation gates — they are
//! lookups on an already-known identity. Treating them as
//! [`SanitizerKind::AuthCheck`] would clear taint on the path past
//! every `users.getUser` call, which is unsound. The narrow scope
//! here is deliberate.
//!
//! ## Guard patterns
//!
//! [`GuardKind::SessionRequired`] declares "if this call appears in a
//! wrapper, the wrapper is plausibly a session-required gate". The
//! matcher list is the union of both sanitiser patterns' matchers —
//! the same call recognised as a value-level sanitiser also registers
//! as a control-flow guard candidate. The actual return-on-null
//! analysis lives in [`crate::flows::auth_bypass_via_wrapper`]; the
//! adapter only contributes "this call counts as a session check".
//!
//! ## Activation
//!
//! Default `is_enabled` — active when the project profile contains an
//! `AuthHint::Clerk` entry at confidence ≥
//! [`crate::adapters::ENABLE_CONFIDENCE_FLOOR`] (`0.60`). The profile
//! crate serialises `Clerk` as `"clerk"`, which matches the `clerk`
//! suffix in this adapter's `auth/clerk` ID. A Better-Auth-only or
//! Auth.js-only profile must not activate this adapter even at high
//! confidence — adapter activation is per-name, not per-kind.
//!
//! [`AUTH_HELPER_NAMES`]: crate::steps::sanitizers::AUTH_HELPER_NAMES

use crate::adapters::{
    AdapterId, AdapterKind, AstMatcher, GuardKind, GuardPattern, SanitiserPattern, SanitizerKind,
    StackAdapter,
};

pub struct ClerkAdapter;

// =============================================================================
// Sanitiser patterns — `auth()` and `currentUser()` from Clerk modules
// =============================================================================
//
// Pattern IDs are stable: reporters group findings by ID, and the
// `auth` / `current-user` split tells consumers which documented Clerk
// call shape the analyser saw. Both clear taint as
// `SanitizerKind::AuthCheck`; the semantic claim is identical.
//
// Each pattern carries two `ImportedCall` matchers — one for the App
// Router entry point (`@clerk/nextjs/server`) and one for the legacy
// / pages-router entry point (`@clerk/nextjs`). Both are documented
// and still appear in production code; recognising both keeps the
// adapter robust across Clerk-on-Next.js versions without forcing the
// rule layer to know about Clerk's module layout.

static SANITISERS: &[SanitiserPattern] = &[
    // `auth()` — server-side helper returning `{ userId, sessionId, ... }`
    // or `null`. The bare-ident `auth` name overlaps with Auth.js's
    // `auth/auth-js/auth` pattern; the module-specifier check on
    // `ImportedCall` is what disambiguates the two.
    SanitiserPattern {
        id: "auth/clerk/auth",
        sanitizer: SanitizerKind::AuthCheck,
        matchers: &[
            AstMatcher::ImportedCall {
                module: "@clerk/nextjs/server",
                name: "auth",
            },
            AstMatcher::ImportedCall {
                module: "@clerk/nextjs",
                name: "auth",
            },
        ],
    },
    // `currentUser()` — returns the full Clerk User object or `null`.
    // Same dual-import rationale as `auth()`; the documented name is
    // shared across both Clerk module specifiers.
    SanitiserPattern {
        id: "auth/clerk/current-user",
        sanitizer: SanitizerKind::AuthCheck,
        matchers: &[
            AstMatcher::ImportedCall {
                module: "@clerk/nextjs/server",
                name: "currentUser",
            },
            AstMatcher::ImportedCall {
                module: "@clerk/nextjs",
                name: "currentUser",
            },
        ],
    },
];

// =============================================================================
// Guard patterns — control-flow gates on session validation
// =============================================================================
//
// Single guard pattern whose matcher list is the union of the two
// sanitiser patterns' matchers. The rule layer
// (`flow/auth-bypass-via-wrapper`) decides whether the surrounding
// wrapper enforces the gate (early return on null, throws, etc.); the
// adapter only contributes "this call counts as a session check".

static GUARDS: &[GuardPattern] = &[GuardPattern {
    id: "auth/clerk/session-required",
    guard: GuardKind::SessionRequired,
    matchers: &[
        AstMatcher::ImportedCall {
            module: "@clerk/nextjs/server",
            name: "auth",
        },
        AstMatcher::ImportedCall {
            module: "@clerk/nextjs",
            name: "auth",
        },
        AstMatcher::ImportedCall {
            module: "@clerk/nextjs/server",
            name: "currentUser",
        },
        AstMatcher::ImportedCall {
            module: "@clerk/nextjs",
            name: "currentUser",
        },
    ],
}];

impl StackAdapter for ClerkAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("auth/clerk")
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
    fn clerk_adapter_exposes_expected_sanitiser_patterns() {
        let sanitisers = ClerkAdapter.sanitisers();
        assert_eq!(sanitisers.len(), 2);
        let ids: Vec<&str> = sanitisers.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"auth/clerk/auth"));
        assert!(ids.contains(&"auth/clerk/current-user"));

        // Both patterns clear taint as `AuthCheck` — the
        // `SanitizerKind::AuthCheck` contract is the load-bearing
        // semantic claim, regardless of which Clerk call shape matched.
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
    fn clerk_adapter_exposes_expected_guard_patterns() {
        let guards = ClerkAdapter.guards();
        assert_eq!(guards.len(), 1);
        assert_eq!(guards[0].id, "auth/clerk/session-required");
        assert_eq!(guards[0].guard, GuardKind::SessionRequired);
    }

    #[test]
    fn clerk_adapter_is_auth_kind() {
        assert_eq!(ClerkAdapter.kind(), AdapterKind::Auth);
        assert_eq!(ClerkAdapter.id(), AdapterId("auth/clerk"));
    }

    #[test]
    fn is_enabled_returns_true_under_clerk_profile() {
        // High-confidence Clerk detection in the profile must activate
        // the adapter via the default `is_enabled` path (matches
        // `auth/<name>` adapter ID suffix against the
        // `AuthHint::Clerk` serde spelling `"clerk"`).
        let profile = ProjectProfile {
            auth_layers: vec![Detected {
                id: AuthHint::Clerk,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(ClerkAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_better_auth_profile() {
        // A Better-Auth-only profile must not activate the Clerk
        // adapter, even at high confidence — adapter activation is
        // per-name, not per-kind. Mirrors the equivalent test on the
        // Better Auth and Auth.js adapter sides.
        let profile = ProjectProfile {
            auth_layers: vec![Detected {
                id: AuthHint::BetterAuth,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!ClerkAdapter.is_enabled(&profile));
    }
}
