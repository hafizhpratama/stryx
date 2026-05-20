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
    // Prisma-shape: `<receiver>.<model>.<method>(...)` where the
    // terminal method is a recognised Prisma write verb. The
    // receiver is either:
    //
    //   - a bare identifier like `prisma` / `db` / `database`
    //     (the legacy shape — most starter templates use this), or
    //   - a property access ending in a Prisma-like name —
    //     `this.prismaService`, `this.prismaClient`, or any
    //     `<x>.prisma` / `<x>.db` access, or a bare identifier
    //     named `prismaService` / `prismaClient`. NestJS apps that
    //     inject a `PrismaService extends PrismaClient` (the
    //     canonical idiom in the official prisma-examples) end up
    //     with `this.prismaService.user.create(...)`, which the
    //     bare-identifier check above misses entirely.
    //
    // The receiver-name heuristic is conservative: only literal
    // prisma-shaped names match. An app with a field accidentally
    // named `prismaService` accepts the FP, but in practice that
    // name almost always means a Prisma client.
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
    is_prisma_receiver(&model_member.object)
}

/// Does this expression name a Prisma client?
///
/// Accepts:
/// - A bare identifier whose name is `prisma` / `db` / `database` /
///   `prismaService` / `prismaClient` (or ends in `PrismaService` /
///   `PrismaClient` for custom subclasses).
/// - A static member access whose terminal property is one of those
///   names (`this.prismaService`, `someService.prisma`).
/// - A CALL whose callee resolves to a prisma-shaped method —
///   `this.prismaService.extendedPrismaClient()`,
///   `<x>.$extends(...)`, `<x>.client(...)`. This catches the
///   `prisma-examples/orm/nest` shape where the controller writes
///   `this.prismaService.extendedPrismaClient().post.create({...})`.
fn is_prisma_receiver(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::Identifier(id) => is_prisma_name(id.name.as_str()),
        Expression::StaticMemberExpression(member) => is_prisma_name(member.property.name.as_str()),
        // Chained-method receivers — `…extendedPrismaClient()` etc. The
        // method name is the signal: any one of a short list of
        // Prisma-augmenting method names rooted on a prisma-shaped
        // receiver counts. We don't recurse into the call's own
        // receiver because the outer property name is already a strong
        // enough signal in practice; deeper validation would mostly
        // catch test mocks at the cost of FN risk.
        Expression::CallExpression(call) => {
            let Some(callee) = call.callee.as_member_expression() else {
                return false;
            };
            let MemberExpression::StaticMemberExpression(method) = callee else {
                return false;
            };
            matches!(
                method.property.name.as_str(),
                "extendedPrismaClient" | "extendedClient" | "$extends" | "client" | "prisma"
            )
        }
        _ => false,
    }
}

fn is_prisma_name(name: &str) -> bool {
    matches!(
        name,
        "prisma" | "db" | "database" | "prismaService" | "prismaClient"
    ) || name.ends_with("PrismaService")
        || name.ends_with("PrismaClient")
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
