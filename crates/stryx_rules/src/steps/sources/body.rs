//! Body-source step ([ADR 0008] slice 8.2).
//!
//! Recognises request-body sources across Next.js (`req.body`,
//! `req.json()`, `req.text()`, `req.formData()`), Hono
//! (`c.req.json()`, `ctx.request.json()`), and bare-identifier
//! shorthands (`request.body`).
//!
//! The predicate logic lives here as freestanding `pub fn`s so it
//! can be reused by callers that have already destructured the AST
//! node — slice 8.2 keeps the legacy wrappers in
//! [`crate::flows::unvalidated_body_to_db`] importing these
//! directly, while the visitor's primary `expr_taint` path routes
//! through the [`BodySource`] step's [`TaintStep::as_source`]
//! dispatch.
//!
//! [ADR 0008]: ../../../../../docs/decisions/0008-taint-step-trait-substrate.md

use stryx_ast::ast::{CallExpression, Expression, MemberExpression};
use stryx_taint::TaintLabel;

use crate::steps::{StepCtx, TaintStep};

/// Body-source recogniser. Stateless; behaves uniformly under the
/// `body_source_active` gate carried in [`StepCtx`].
#[derive(Debug, Default, Clone, Copy)]
pub struct BodySource;

impl TaintStep for BodySource {
    fn as_source(&self, ctx: &StepCtx<'_, '_>, expr: &Expression<'_>) -> Option<TaintLabel> {
        if !ctx.body_source_active {
            return None;
        }
        let matched = match expr {
            Expression::StaticMemberExpression(m) => {
                is_request_body_member(&m.object, m.property.name.as_str())
            }
            Expression::CallExpression(c) => is_body_source_call(c),
            _ => false,
        };
        if matched {
            Some(TaintLabel::UserInput)
        } else {
            None
        }
    }
}

/// `req.body` / `request.body` / `c.req.body` / `ctx.request.body`.
pub fn is_request_body_member(object: &Expression<'_>, prop: &str) -> bool {
    if prop != "body" {
        return false;
    }
    is_request_like_expr(object)
}

/// `req.json()` / `req.text()` / `req.formData()` / `req.arrayBuffer()`
/// / `req.blob()`, plus the Hono variants chaining through a context
/// object (`c.req.json()`, `ctx.request.json()`, etc.).
pub fn is_body_source_call(call: &CallExpression<'_>) -> bool {
    let Some(callee) = call.callee.as_member_expression() else {
        return false;
    };
    let MemberExpression::StaticMemberExpression(method_member) = callee else {
        return false;
    };
    if !matches!(
        method_member.property.name.as_str(),
        "json" | "text" | "formData" | "arrayBuffer" | "blob"
    ) {
        return false;
    }
    is_request_like_expr(&method_member.object)
}

/// Matches an expression that we treat as a request object: either
/// a bare `req`/`request`/`ctx`/`c` identifier, or a Hono-style
/// `c.req` / `ctx.request` chain.
fn is_request_like_expr(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::Identifier(id) => {
            matches!(id.name.as_str(), "req" | "request" | "ctx" | "c")
        }
        Expression::StaticMemberExpression(m) => {
            if !matches!(m.property.name.as_str(), "req" | "request") {
                return false;
            }
            matches!(
                &m.object,
                Expression::Identifier(id) if matches!(id.name.as_str(), "ctx" | "c")
            )
        }
        _ => false,
    }
}
