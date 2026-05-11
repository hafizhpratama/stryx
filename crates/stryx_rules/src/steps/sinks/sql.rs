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
    if prop == "query"
        && matches!(
            &method.object,
            Expression::Identifier(id)
                if matches!(id.name.as_str(), "pool" | "client" | "db" | "connection")
        )
    {
        return true;
    }

    false
}
