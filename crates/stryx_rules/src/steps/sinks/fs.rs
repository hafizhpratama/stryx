//! Filesystem-call sink step — `fs.<method>(path, ...)` /
//! `fsPromises.<method>(path, ...)` / `fs.promises.<method>(path, ...)`
//! recogniser for [`crate::flows::path_traversal::PathTraversal`].
//!
//! Recognised methods:
//!
//! - Read: `readFile` / `readFileSync` / `createReadStream`
//! - Write: `writeFile` / `writeFileSync` / `createWriteStream` /
//!   `appendFile` / `appendFileSync`
//! - Delete: `unlink` / `unlinkSync` / `rm` / `rmSync` / `rmdir`
//!   / `rmdirSync`
//! - Stat: `access` / `accessSync` / `stat` / `statSync` /
//!   `lstat` / `lstatSync` / `realpath` / `realpathSync`
//!
//! Recognised receivers (the namespace before the dot):
//!
//! - `fs.<method>(...)` — the standard CommonJS shape
//! - `fsPromises.<method>(...)` — Node's promise-flavoured fs
//! - `fs.promises.<method>(...)` — the namespaced promise interface
//!
//! Bare imports (`import { readFile } from 'fs'; readFile(...)`)
//! are not recognised in slice 1 — the method names are common
//! enough that bare matching needs scope-aware import tracking to
//! avoid FPs on unrelated functions.
//!
//! Severity hint: `High` — path-traversal can leak arbitrary
//! filesystem contents (`/etc/passwd`, `.env`, application source)
//! or overwrite trusted files. CWE-22 / CWE-23.

use stryx_ast::ast::{CallExpression, Expression, MemberExpression};
use stryx_core::Severity;

use crate::steps::{SinkSpec, StepCtx, TaintStep};

/// Filesystem-call sink recogniser. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct FsSink;

impl TaintStep for FsSink {
    fn as_sink(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> Option<SinkSpec> {
        if is_fs_sink_call(call) {
            Some(SinkSpec {
                severity_hint: Severity::High,
            })
        } else {
            None
        }
    }
}

/// True iff `call`'s callee matches one of the recognised
/// `<receiver>.<fs-method>` shapes documented at the module level.
pub fn is_fs_sink_call(call: &CallExpression<'_>) -> bool {
    let Some(member) = call.callee.as_member_expression() else {
        return false;
    };
    let MemberExpression::StaticMemberExpression(method) = member else {
        return false;
    };
    if !is_fs_method_name(method.property.name.as_str()) {
        return false;
    }
    is_fs_receiver(&method.object)
}

fn is_fs_method_name(name: &str) -> bool {
    matches!(
        name,
        // Read.
        "readFile"
            | "readFileSync"
            | "createReadStream"
            // Write.
            | "writeFile"
            | "writeFileSync"
            | "createWriteStream"
            | "appendFile"
            | "appendFileSync"
            // Delete.
            | "unlink"
            | "unlinkSync"
            | "rm"
            | "rmSync"
            | "rmdir"
            | "rmdirSync"
            // Stat / metadata.
            | "access"
            | "accessSync"
            | "stat"
            | "statSync"
            | "lstat"
            | "lstatSync"
            | "realpath"
            | "realpathSync"
    )
}

fn is_fs_receiver(receiver: &Expression<'_>) -> bool {
    match receiver {
        Expression::Identifier(id) => matches!(id.name.as_str(), "fs" | "fsPromises"),
        // `fs.promises.<method>(...)` — the namespaced promise interface.
        Expression::StaticMemberExpression(m) => {
            if m.property.name != "promises" {
                return false;
            }
            matches!(&m.object, Expression::Identifier(id) if id.name == "fs")
        }
        _ => false,
    }
}
