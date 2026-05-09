//! Stryx rule library. The trait is intentionally narrow for v0.0.1: a rule
//! consumes a `ParsedFile` and emits findings. The richer `interests()` /
//! `taint_signature()` / `scope()` methods land alongside `stryx_taint`.

pub mod generic;
pub mod registry;

use stryx_ast::ParsedFile;
use stryx_core::{Finding, RuleId, Severity};

/// Per-rule metadata surfaced by `--list-rules` and reporters.
#[derive(Debug, Clone, Copy)]
pub struct RuleMeta {
    pub id: RuleId,
    pub default_severity: Severity,
    pub description: &'static str,
}

/// Context handed to a rule each time it runs against a parsed file.
/// Kept as a struct (not bare arguments) so future fields — index handle,
/// taint summaries, configuration — don't break existing rules.
pub struct RuleContext<'a, 'b> {
    pub file: &'a ParsedFile<'b>,
}

/// The minimal Rule trait. Returns owned findings; the engine handles
/// dedup, severity overrides, and reporter formatting.
pub trait Rule: Send + Sync {
    fn meta(&self) -> RuleMeta;
    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding>;
}

pub use registry::{builtin_rules, RuleRegistry};
