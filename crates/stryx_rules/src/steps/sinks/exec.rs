//! Command-execution sink step — Node.js `child_process` API
//! recogniser for the `flow/command-injection-via-exec` rule.
//!
//! Recognised shapes:
//!
//! - Bare identifier callees `exec` / `execSync` / `execFile` /
//!   `execFileSync` / `spawn` / `spawnSync` (after a destructured
//!   `import { exec } from "child_process"`).
//! - Member calls `<x>.<method>` where `<x>` is one of the
//!   conventional namespace identifiers (`cp`, `childProcess`,
//!   `child_process`).
//!
//! The first argument of any matched call is the
//! command/binary-path the caller controls. Body taint there is
//! the rule's finding condition.
//!
//! Severity hint is `Critical` — command injection is OWASP A03
//! and CWE-78, and the consequence is arbitrary code execution
//! under the application's process identity.

use stryx_ast::ast::{CallExpression, Expression, MemberExpression};
use stryx_core::Severity;

use crate::steps::{SinkSpec, StepCtx, TaintStep};

/// The six recognised `child_process` method/function names.
const EXEC_METHODS: &[&str] = &[
    "exec",
    "execSync",
    "execFile",
    "execFileSync",
    "spawn",
    "spawnSync",
];

/// Conventional namespace identifiers for `child_process` imports.
/// `cp` (the short alias), `childProcess` (camelCase form), and
/// the raw module name `child_process` itself.
const EXEC_RECEIVERS: &[&str] = &["cp", "childProcess", "child_process"];

/// Exec-call sink recogniser. Stateless; the [`StepCtx`] is unused.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExecSink;

impl TaintStep for ExecSink {
    fn as_sink(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> Option<SinkSpec> {
        if is_exec_sink_call(call) {
            Some(SinkSpec {
                severity_hint: Severity::Critical,
            })
        } else {
            None
        }
    }
}

/// True iff `call` is one of the recognised `child_process` shapes.
pub fn is_exec_sink_call(call: &CallExpression<'_>) -> bool {
    match &call.callee {
        // Bare ident: `exec(...)`, `execSync(...)`, etc. The
        // pattern produced by `import { exec } from "child_process"`.
        Expression::Identifier(id) => EXEC_METHODS.contains(&id.name.as_str()),
        // Member: `<x>.exec(...)` where `<x>` is one of the
        // conventional namespace names.
        Expression::StaticMemberExpression(_) => {
            let Some(MemberExpression::StaticMemberExpression(method)) =
                call.callee.as_member_expression()
            else {
                return false;
            };
            if !EXEC_METHODS.contains(&method.property.name.as_str()) {
                return false;
            }
            matches!(
                &method.object,
                Expression::Identifier(id) if EXEC_RECEIVERS.contains(&id.name.as_str())
            )
        }
        _ => false,
    }
}
