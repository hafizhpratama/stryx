//! Auth-check step ([ADR 0008] slice 8.3b).
//!
//! Recognises calls to authentication helpers — `getServerSession`,
//! `auth.protect()`, `clerk.currentUser()`, `lucia.validateRequest()`,
//! `requireSession`, and similar. These calls don't sanitise a value
//! in the parser sense; they gate execution on a verified session.
//! Modelled as a sanitiser because the trait's `as_sanitizer` role
//! is "this call clears taint at the function-control level", which
//! fits both shapes — a future role refinement (e.g. a separate
//! `as_auth_gate` for control-flow-only checks) is contemplated but
//! not required at this phase.
//!
//! [`AUTH_HELPER_NAMES`] and the per-call predicate
//! [`call_invokes_auth_helper`] are `pub` so the body-walker
//! [`crate::flows::auth_bypass_via_wrapper::contains_auth_helper_call`]
//! can keep consuming them directly during the migration.
//!
//! [ADR 0008]: ../../../../../docs/decisions/0008-taint-step-trait-substrate.md

use stryx_ast::ast::{CallExpression, ChainElement, Expression};

use crate::steps::{StepCtx, TaintStep};

/// Recognised auth-helper function names. A wrapper whose body
/// invokes any of these (anywhere — including nested arrow returns)
/// is treated as "actually verifies authentication".
///
/// Bare names match `getServerSession(opts)`; member-access matches
/// `auth.protect()`, `clerk.currentUser()`, `lucia.validateRequest()`.
pub const AUTH_HELPER_NAMES: &[&str] = &[
    "getServerSession",
    "getSession",
    "auth",
    "validateRequest",
    "getAuth",
    "currentUser",
    "getUser",
    "requireSession",
    "requireUser",
    "protect",
    "isAuthenticated",
    "verifyToken",
    "verifySession",
];

/// Auth-check sanitiser recogniser. Stateless; the [`StepCtx`] is
/// unused — auth recognition is purely syntactic over the callee
/// shape.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuthCheckSanitizer;

impl TaintStep for AuthCheckSanitizer {
    fn as_sanitizer(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> bool {
        call_invokes_auth_helper(call)
    }
}

/// True iff `call`'s callee is one of [`AUTH_HELPER_NAMES`]. Handles
/// bare-identifier calls (`getServerSession(opts)`), static-member
/// calls (`auth.protect()`), and optional-chain forms
/// (`auth?.()`, `auth?.protect()`).
pub fn call_invokes_auth_helper(call: &CallExpression<'_>) -> bool {
    let name = match &call.callee {
        Expression::Identifier(id) => id.name.as_str(),
        Expression::StaticMemberExpression(m) => m.property.name.as_str(),
        Expression::ChainExpression(c) => {
            // `auth?.()` / `auth?.protect()`
            return match &c.expression {
                ChainElement::CallExpression(inner) => call_invokes_auth_helper(inner),
                _ => false,
            };
        }
        _ => return false,
    };
    AUTH_HELPER_NAMES.contains(&name)
}
