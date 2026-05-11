//! Response-body sink step ([ADR 0008] slice 8.4b).
//!
//! Recognises calls and constructions that deliver a value into an
//! HTTP response body across the major TypeScript framework
//! conventions:
//!
//! - **Next.js App Router** — `Response.json(...)`,
//!   `NextResponse.json(...)`, `new Response(body)`.
//! - **Express / Pages Router** — `res.json(...)`, `res.send(...)`,
//!   `res.end(...)`, `res.write(...)`.
//! - **Fastify** — `reply.send(...)`.
//! - **Hono** — `c.json(...)`, `c.text(...)`, `c.html(...)`,
//!   `c.body(...)`, plus the `ctx`-aliased variants.
//!
//! Free-standing predicates [`response_sink_label`] and
//! [`is_response_constructor`] are `pub` so the legacy call sites in
//! [`crate::flows::secret_to_response`] can keep using them through
//! the migration. The trait method [`TaintStep::as_sink`] only
//! covers `CallExpression` (the `new Response(...)` shape is
//! `NewExpression`, which the trait surface doesn't include — that
//! call site stays on the freestanding predicate).
//!
//! [ADR 0008]: ../../../../../docs/decisions/0008-taint-step-trait-substrate.md

use stryx_ast::ast::{CallExpression, Expression, MemberExpression};
use stryx_core::Severity;

use crate::steps::{SinkSpec, StepCtx, TaintStep};

const RESPONSE_SINK_SPEC: SinkSpec = SinkSpec {
    severity_hint: Severity::Critical,
};

/// Response-body sink recogniser. Stateless; the [`StepCtx`] is
/// unused — recognition is purely syntactic over the callee shape.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResponseSink;

impl TaintStep for ResponseSink {
    fn as_sink(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> Option<SinkSpec> {
        if response_sink_label(call).is_some() {
            Some(RESPONSE_SINK_SPEC)
        } else {
            None
        }
    }
}

/// Returns a label like `"Response.json"` / `"res.send"` /
/// `"c.json"` when `call` is a recognised response-body sink, or
/// `None` otherwise.
pub fn response_sink_label(call: &CallExpression<'_>) -> Option<String> {
    let MemberExpression::StaticMemberExpression(method) = call.callee.as_member_expression()?
    else {
        return None;
    };
    let prop = method.property.name.as_str();
    let receiver = match &method.object {
        Expression::Identifier(id) => id.name.as_str().to_string(),
        // `ctx.json(...)` is fine via the Identifier path. Hono's
        // `c.req` chain isn't a response sink; skip member receivers
        // entirely.
        _ => return None,
    };

    let is_sink = match (receiver.as_str(), prop) {
        // Express / Pages Router style.
        ("res", "json" | "send" | "end" | "write") => true,
        // Fastify.
        ("reply", "send") => true,
        // Hono.
        ("c" | "ctx", "json" | "text" | "html" | "body") => true,
        // Web standard / Next.js App Router static helpers.
        ("Response" | "NextResponse", "json") => true,
        _ => false,
    };
    if !is_sink {
        return None;
    }
    Some(format!("{receiver}.{prop}"))
}

/// `new Response(...)` — bare `Response` constructor call. The
/// trait method [`TaintStep::as_sink`] takes a `CallExpression`,
/// not a `NewExpression`, so this predicate is kept freestanding
/// for the consuming rule's `NewExpression` arm.
pub fn is_response_constructor(callee: &Expression<'_>) -> bool {
    matches!(
        callee,
        Expression::Identifier(id) if id.name == "Response"
    )
}
