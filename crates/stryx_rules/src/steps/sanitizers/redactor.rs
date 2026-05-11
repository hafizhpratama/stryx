//! Redactor-style sanitiser step ([ADR 0008] slice 8.3c).
//!
//! Recognises calls that *transform* a secret-shaped value into a
//! derived non-secret. Two syntactic shapes:
//!
//! - `redact(x)` / `mask(x)` / `fingerprint(x)` / `hash(x)` — bare
//!   or member-call forms. Used by [`crate::flows::secret_to_response`]
//!   to strip the Secret label.
//! - `Boolean(secret)` — explicit constructor coercion that returns
//!   a presence check, no value content.
//!
//! Free-standing predicates [`is_redactor_call`] and
//! [`is_boolean_coercion`] are `pub` so the legacy call site in
//! [`crate::flows::secret_to_response`] can keep using them through
//! the migration. The trait method [`TaintStep::as_sanitizer`]
//! returns `true` if either matches.
//!
//! [ADR 0008]: ../../../../../docs/decisions/0008-taint-step-trait-substrate.md

use stryx_ast::ast::{CallExpression, Expression};

use crate::steps::{StepCtx, TaintStep};

/// Recognised redaction-helper function names.
pub const REDACT_FN_NAMES: &[&str] = &["redact", "mask", "fingerprint", "hash"];

/// Redactor sanitiser recogniser. Stateless; the [`StepCtx`] is
/// unused.
#[derive(Debug, Default, Clone, Copy)]
pub struct RedactorSanitizer;

impl TaintStep for RedactorSanitizer {
    fn as_sanitizer(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> bool {
        is_redactor_call(call) || is_boolean_coercion(call)
    }
}

/// Recognises `redact(x)`, `mask(x)`, `fingerprint(x)`, `hash(x)`,
/// or the same names on a member receiver (`utils.redact(x)`,
/// `crypto.hash(x)`).
pub fn is_redactor_call(call: &CallExpression<'_>) -> bool {
    let name = match &call.callee {
        Expression::Identifier(id) => id.name.as_str(),
        Expression::StaticMemberExpression(m) => m.property.name.as_str(),
        _ => return false,
    };
    REDACT_FN_NAMES.contains(&name)
}

/// `Boolean(secret)` produces a derived non-secret bool. The
/// double-bang shorthand `!!secret` is handled via UnaryExpression
/// recognition elsewhere (not by this predicate); only the explicit
/// constructor call matches here.
pub fn is_boolean_coercion(call: &CallExpression<'_>) -> bool {
    matches!(
        &call.callee,
        Expression::Identifier(id) if id.name == "Boolean"
    )
}
