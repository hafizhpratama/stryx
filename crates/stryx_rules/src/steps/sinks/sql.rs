//! SQL-call sink step — raw-SQL escape-hatch recogniser for the
//! `flow/sql-injection` rule.
//!
//! Recognised shapes:
//!
//! - `<x>.$queryRawUnsafe(<sql>, ...)` — Prisma's explicit
//!   non-parameterised path.
//! - `<x>.$executeRawUnsafe(<sql>, ...)` — Prisma's explicit
//!   non-parameterised path for DDL/DML.
//! - `<x>.raw(<sql>, ...)` where `<x>` is the bare identifier
//!   `sql` — Drizzle's escape hatch from the parameterised
//!   tagged-template `sql\`...\``.
//! - `<x>.query(<sql>, ...)` where `<x>` is a conventional
//!   database-connection name (`pool` / `client` / `db` /
//!   `connection`) — node-postgres / mysql2 raw query path.
//! - `<x>.<y>.query(<sql>, ...)` where the LAST segment of the
//!   receiver chain is a conventional connection name —
//!   catches Sequelize's canonical `db.sequelize.query(<sql>)`,
//!   TypeORM's `dataSource.query(...)`, and similar
//!   injected-property shapes that the bare-identifier check
//!   above misses.
//!
//! Severity hint is `Critical` — SQL injection is OWASP A03:2021
//! and CWE-89, with database compromise and data exfiltration
//! consistently across all DB engines.
//!
//! Tagged-template forms (`prisma.$queryRaw\`...\``,
//! `prisma.$executeRaw\`...\``, Drizzle's `sql\`...\``) are
//! deliberately *not* recognised — they generate parameterised
//! SQL and are safe by construction. They would not match the
//! call-expression shape this recogniser inspects in the first
//! place.

use stryx_ast::ast::{CallExpression, Expression, MemberExpression};
use stryx_core::Severity;

use crate::steps::{SinkSpec, StepCtx, TaintStep};

/// SQL-call sink recogniser. Stateless; the [`StepCtx`] is unused.
#[derive(Debug, Default, Clone, Copy)]
pub struct SqlSink;

impl TaintStep for SqlSink {
    fn as_sink(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> Option<SinkSpec> {
        if is_sql_sink_call(call) {
            Some(SinkSpec {
                severity_hint: Severity::Critical,
            })
        } else {
            None
        }
    }
}

/// True iff `call` is one of the recognised raw-SQL escape-hatch
/// shapes. The first argument of such a call is the SQL string —
/// callers (the flow rule's visitor) inspect that for body taint.
pub fn is_sql_sink_call(call: &CallExpression<'_>) -> bool {
    let Some(MemberExpression::StaticMemberExpression(method)) = call.callee.as_member_expression()
    else {
        return false;
    };
    let prop = method.property.name.as_str();

    // Prisma's explicit non-parameterised methods — any receiver.
    if matches!(prop, "$queryRawUnsafe" | "$executeRawUnsafe") {
        return true;
    }

    // Drizzle's escape hatch: bare `sql.raw(...)`.
    if prop == "raw"
        && matches!(
            &method.object,
            Expression::Identifier(id) if id.name == "sql"
        )
    {
        return true;
    }

    // node-postgres / mysql2 raw query: `<conn>.query(<sql>, ...)`
    // where `<conn>` is one of the conventional bare-identifier
    // database-connection names.
    if prop == "query" && is_conventional_db_receiver(&method.object) {
        return true;
    }

    false
}

/// Match a "conventional DB receiver" — either a bare identifier
/// whose name is one of the canonical pool/client names, or a
/// member-access chain whose LAST segment is one of those names.
/// This recognises both `pool.query(...)` (bare) and the
/// Sequelize/TypeORM injection-via-instance shapes
/// (`db.sequelize.query(...)`, `this.dataSource.query(...)`).
///
/// Walking the last segment only — rather than every segment in
/// the chain — is deliberate: it costs O(1) per call, keeps the
/// rule out of class-hierarchy reasoning, and the conventional
/// names are specific enough (`sequelize`, `db`, `pool`, ...) that
/// a chain ending in one of them is almost always a real DB
/// receiver. Apps that name an unrelated field `db` accept the FP.
fn is_conventional_db_receiver(expr: &Expression<'_>) -> bool {
    let name = match expr {
        Expression::Identifier(id) => id.name.as_str(),
        Expression::StaticMemberExpression(member) => member.property.name.as_str(),
        _ => return false,
    };
    matches!(
        name,
        "pool" | "client" | "db" | "connection" | "sequelize" | "dataSource" | "knex"
    )
}
