//! Redirect-call sink step — recogniser for
//! [`crate::flows::ssrf_via_fetch`]'s sibling rule
//! [`crate::flows::redirect_open::RedirectOpen`].
//!
//! Recognised shapes:
//!
//! - `NextResponse.redirect(url, ...)` — Next.js App Router server
//!   responses.
//! - `Response.redirect(url, ...)` — the Web platform built-in.
//! - `redirect(url)` — bare callable, conventionally imported from
//!   `next/navigation` or framework helpers. Severity is treated
//!   the same as the namespaced shapes since the bare-identifier
//!   form is common in tutorial-style route handlers.
//! - `<ident>.redirect(url, ...)` — covers Express-style
//!   `res.redirect(url)`, `reply.redirect(url)` (Fastify), and
//!   chain-style framework adapters.
//!
//! Severity hint is `High` — unvalidated redirects are CWE-601
//! (Open Redirect), trust-transfer-grade phishing surface.

use stryx_ast::ast::{CallExpression, Expression, MemberExpression};
use stryx_core::Severity;

use crate::steps::{SinkSpec, StepCtx, TaintStep};

/// Redirect-call sink recogniser. Stateless; the [`StepCtx`] is unused.
#[derive(Debug, Default, Clone, Copy)]
pub struct RedirectSink;

impl TaintStep for RedirectSink {
    fn as_sink(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> Option<SinkSpec> {
        if is_redirect_sink_call(call) {
            Some(SinkSpec {
                severity_hint: Severity::High,
            })
        } else {
            None
        }
    }
}

/// True iff `call` is one of the recognised redirect shapes — bare
/// `redirect(...)`, `<ident>.redirect(...)`, or
/// `NextResponse.redirect(...)` / `Response.redirect(...)`.
pub fn is_redirect_sink_call(call: &CallExpression<'_>) -> bool {
    match &call.callee {
        // Bare `redirect(url)` — `next/navigation` convention.
        Expression::Identifier(id) => id.name == "redirect",
        Expression::StaticMemberExpression(_) => {
            let Some(member) = call.callee.as_member_expression() else {
                return false;
            };
            let MemberExpression::StaticMemberExpression(method) = member else {
                return false;
            };
            if method.property.name != "redirect" {
                return false;
            }
            // Any receiver — `res.redirect`, `reply.redirect`,
            // `NextResponse.redirect`, `Response.redirect`, etc.
            // The `.redirect` method name is specific enough that
            // false positives on this shape are unlikely; tightening
            // is reserved for if/when a real-world FP surfaces.
            matches!(
                &method.object,
                Expression::Identifier(_) | Expression::StaticMemberExpression(_)
            )
        }
        _ => false,
    }
}
