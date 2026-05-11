//! HTTP-call sink step — outbound `fetch` / `axios.<method>` / `got`
//! recogniser for the `flow/ssrf-via-fetch` rule.
//!
//! Recognised shapes:
//!
//! - Bare `fetch(url, ...)` (the global Fetch API in Next.js
//!   App Router runtimes).
//! - `axios.<method>(url, ...)` for the standard axios methods
//!   (`get`, `post`, `put`, `patch`, `delete`, `head`, `options`,
//!   `request`).
//! - `got(url, ...)` and `got.<method>(url, ...)`.
//!
//! Severity hint is `High` — SSRF is in the OWASP Top 10 and the
//! consequence (internal-metadata exfiltration, internal-service
//! pivots) is consistently high-impact across cloud deployments.

use stryx_ast::ast::{CallExpression, Expression, MemberExpression};
use stryx_core::Severity;

use crate::steps::{SinkSpec, StepCtx, TaintStep};

/// HTTP-call sink recogniser. Stateless; the [`StepCtx`] is unused.
#[derive(Debug, Default, Clone, Copy)]
pub struct FetchSink;

impl TaintStep for FetchSink {
    fn as_sink(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> Option<SinkSpec> {
        if is_http_sink_call(call) {
            Some(SinkSpec {
                severity_hint: Severity::High,
            })
        } else {
            None
        }
    }
}

/// True iff `call` is one of the recognised outbound HTTP shapes
/// — bare `fetch(...)`, `axios.<method>(...)`, `got(...)`, or
/// `got.<method>(...)`.
pub fn is_http_sink_call(call: &CallExpression<'_>) -> bool {
    match &call.callee {
        Expression::Identifier(id) => {
            matches!(id.name.as_str(), "fetch" | "got")
        }
        Expression::StaticMemberExpression(_) => {
            let Some(member) = call.callee.as_member_expression() else {
                return false;
            };
            let MemberExpression::StaticMemberExpression(method) = member else {
                return false;
            };
            let prop = method.property.name.as_str();
            // `axios.<method>(...)` — standard methods.
            if let Expression::Identifier(receiver) = &method.object
                && receiver.name == "axios"
                && matches!(
                    prop,
                    "get" | "post"
                        | "put"
                        | "patch"
                        | "delete"
                        | "head"
                        | "options"
                        | "request"
                )
            {
                return true;
            }
            // `got.<method>(...)` — the `got` library's per-verb methods.
            if let Expression::Identifier(receiver) = &method.object
                && receiver.name == "got"
                && matches!(
                    prop,
                    "get" | "post" | "put" | "patch" | "delete" | "head"
                )
            {
                return true;
            }
            false
        }
        _ => false,
    }
}
