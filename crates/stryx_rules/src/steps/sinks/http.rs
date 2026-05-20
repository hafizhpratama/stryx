//! HTTP-call sink step — outbound HTTP-client recogniser for the
//! `flow/ssrf-via-fetch` rule.
//!
//! Recognised shapes:
//!
//! - Bare `fetch(url, ...)` (the global Fetch API in Next.js
//!   App Router runtimes).
//! - Bare `got(url, ...)`, `needle(url, ...)`, `request(url, ...)`,
//!   `superagent(url, ...)` — common Node HTTP clients used as
//!   the bare callable.
//! - `axios.<method>(url, ...)` for the standard axios methods.
//! - `got.<method>(url, ...)` for got's per-verb shorthands.
//! - `needle.<method>(url, ...)` — `needle.get`, `needle.post`,
//!   etc. NodeGoat's research route uses this exact shape.
//! - `request.<method>(url, ...)` — the `request` package's
//!   per-verb shorthands (legacy but still common).
//! - `superagent.<method>(url, ...)` — superagent's per-verb
//!   methods.
//! - `http.<method>(url, ...)` and `https.<method>(url, ...)`
//!   for the Node built-ins (`get` and `request`).
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

/// Standard HTTP verb method names used across axios/got/needle/
/// request/superagent. Centralised so adding `connect` or `trace`
/// later only touches one place.
const HTTP_VERBS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "request",
];

/// Node built-in `http` / `https` modules expose `get` and `request`
/// only — kept separate so the broader verb list does not introduce
/// FPs against unrelated `http`-named identifiers using methods like
/// `.options(...)`.
const NODE_HTTP_VERBS: &[&str] = &["get", "request"];

/// True iff `call` is one of the recognised outbound HTTP shapes.
/// Conservative on the receiver name (must be a known HTTP-client
/// identifier or a Node built-in module name) to keep FPs low.
pub fn is_http_sink_call(call: &CallExpression<'_>) -> bool {
    match &call.callee {
        // Bare-callable forms: `fetch(url)`, `got(url)`, etc. Some
        // libraries are imported as the default callable (`needle`,
        // `request`, `superagent`) and accept the URL as the first
        // positional argument.
        Expression::Identifier(id) => matches!(
            id.name.as_str(),
            "fetch" | "got" | "needle" | "request" | "superagent"
        ),

        Expression::StaticMemberExpression(_) => {
            let Some(MemberExpression::StaticMemberExpression(method)) =
                call.callee.as_member_expression()
            else {
                return false;
            };
            let prop = method.property.name.as_str();

            let Expression::Identifier(receiver) = &method.object else {
                return false;
            };

            match receiver.name.as_str() {
                // axios.<verb>(url, ...)
                "axios" => HTTP_VERBS.contains(&prop),
                // got/needle/request/superagent share the same per-
                // verb shorthand surface.
                "got" | "needle" | "request" | "superagent" => HTTP_VERBS.contains(&prop),
                // Node built-ins: `http.get(...)` / `http.request(...)`
                // (and HTTPS equivalents). Restricted to the two real
                // methods these modules expose to avoid lighting up
                // unrelated identifiers named `http`.
                "http" | "https" => NODE_HTTP_VERBS.contains(&prop),
                _ => false,
            }
        }
        _ => false,
    }
}
