//! Database write sink steps ([ADR 0008] slice 8.4).
//!
//! Three syntactic shapes covered:
//!
//! - **Prisma** — `<prisma|db|database>.<model>.{create,update,delete,
//!   upsert,createMany,...}(...)`. Receiver shape is fixed (two-level
//!   member chain rooted on a `prisma` / `db` / `database` identifier);
//!   method must be one of the recognised write verbs.
//! - **Drizzle** — `<x>.insert(table).values(arg)` or
//!   `<x>.update(table).set(arg)`. The terminal call's method is
//!   `values` or `set`, and the call's receiver is itself an
//!   `.insert(...)` or `.update(...)` call.
//! - **TypeORM / Mongoose** — `<receiver>.{save,insert,upsert}(arg)`.
//!   Receiver shape is unconstrained — these verbs are DB-specific
//!   enough that any tainted argument reaching them is worth flagging.
//!
//! Free-standing predicates [`is_db_write_sink`],
//! [`is_prisma_write_sink`], [`is_drizzle_write_sink`], and
//! [`is_orm_write_sink`] are `pub` so the legacy call sites in
//! [`crate::flows::unvalidated_body_to_db`] can keep using them
//! through the migration (Prisma's where-vs-data split also depends
//! on the Prisma-specific predicate being directly callable).
//!
//! [ADR 0008]: ../../../../../docs/decisions/0008-taint-step-trait-substrate.md

use stryx_ast::ast::{CallExpression, Expression, MemberExpression};
use stryx_core::Severity;

use crate::steps::{SinkSpec, StepCtx, TaintStep};

const DB_WRITE_SINK_SPEC: SinkSpec = SinkSpec {
    severity_hint: Severity::High,
};

/// Prisma write sink (`prisma.user.create(...)` etc.).
#[derive(Debug, Default, Clone, Copy)]
pub struct PrismaWriteSink;

impl TaintStep for PrismaWriteSink {
    fn as_sink(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> Option<SinkSpec> {
        if is_prisma_write_sink(call) {
            Some(DB_WRITE_SINK_SPEC)
        } else {
            None
        }
    }
}

/// Drizzle write sink (`db.insert(t).values(x)` / `db.update(t).set(x)`).
#[derive(Debug, Default, Clone, Copy)]
pub struct DrizzleWriteSink;

impl TaintStep for DrizzleWriteSink {
    fn as_sink(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> Option<SinkSpec> {
        if is_drizzle_write_sink(call) {
            Some(DB_WRITE_SINK_SPEC)
        } else {
            None
        }
    }
}

/// TypeORM / Mongoose-ish write sink (`<x>.save(...)`,
/// `<x>.insert(...)`, `<x>.upsert(...)`).
#[derive(Debug, Default, Clone, Copy)]
pub struct OrmWriteSink;

impl TaintStep for OrmWriteSink {
    fn as_sink(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> Option<SinkSpec> {
        if is_orm_write_sink(call) {
            Some(DB_WRITE_SINK_SPEC)
        } else {
            None
        }
    }
}

/// Top-level sink matcher: returns true if `call` is a DB write
/// across any recognised ORM. Composes the three shape predicates.
pub fn is_db_write_sink(call: &CallExpression<'_>) -> bool {
    is_prisma_write_sink(call) || is_drizzle_write_sink(call) || is_orm_write_sink(call)
}

pub fn is_prisma_write_sink(call: &CallExpression<'_>) -> bool {
    // Prisma-shape: <prisma|db|database>.<model>.<method>
    const SINK_METHODS: &[&str] = &[
        "create",
        "createMany",
        "createManyAndReturn",
        "update",
        "updateMany",
        "upsert",
        "delete",
        "deleteMany",
    ];

    let Some(callee) = call.callee.as_member_expression() else {
        return false;
    };
    let MemberExpression::StaticMemberExpression(method) = callee else {
        return false;
    };
    if !SINK_METHODS.contains(&method.property.name.as_str()) {
        return false;
    }
    let Expression::StaticMemberExpression(model_member) = &method.object else {
        return false;
    };
    let Expression::Identifier(root_id) = &model_member.object else {
        return false;
    };
    matches!(root_id.name.as_str(), "prisma" | "db" | "database")
}

pub fn is_drizzle_write_sink(call: &CallExpression<'_>) -> bool {
    // Drizzle-shape: `<x>.insert(table).values(arg)` /
    // `<x>.update(table).set(arg)`. The terminal call is
    // `<chain>.values` or `<chain>.set` and the chain itself
    // contains an `.insert` or `.update` call.
    let Some(callee) = call.callee.as_member_expression() else {
        return false;
    };
    let MemberExpression::StaticMemberExpression(terminal) = callee else {
        return false;
    };
    let expected_inner = match terminal.property.name.as_str() {
        "values" => "insert",
        "set" => "update",
        _ => return false,
    };
    let Expression::CallExpression(inner_call) = &terminal.object else {
        return false;
    };
    let Some(inner_callee) = inner_call.callee.as_member_expression() else {
        return false;
    };
    let MemberExpression::StaticMemberExpression(inner_method) = inner_callee else {
        return false;
    };
    inner_method.property.name.as_str() == expected_inner
}

pub fn is_orm_write_sink(call: &CallExpression<'_>) -> bool {
    // TypeORM / Mongoose / generic ORM: `<receiver>.save(...)`,
    // `<receiver>.insert(...)`, `<receiver>.upsert(...)`. The
    // receiver shape is unconstrained — these verbs are DB-specific
    // enough that any tainted argument arriving here is worth
    // flagging.
    if call.arguments.is_empty() {
        return false;
    }
    let Some(callee) = call.callee.as_member_expression() else {
        return false;
    };
    let MemberExpression::StaticMemberExpression(method) = callee else {
        return false;
    };
    matches!(method.property.name.as_str(), "save" | "insert" | "upsert")
}
