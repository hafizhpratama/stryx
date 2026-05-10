//! Stryx rule library.
//!
//! Engine pipeline (slice 2):
//!
//! 1. **Extract pass.** For every file in the scan, each rule's
//!    [`Rule::extract`] method may return a [`FileSummary`] contribution
//!    that is merged into a project-wide [`ProjectIndex`].
//! 2. **Run pass.** Each rule's [`Rule::run`] method is invoked with a
//!    [`RuleContext`] carrying both the parsed file *and* a read-only
//!    reference to the merged index, so cross-file lookups (e.g.
//!    "does this imported function sink the body to the database?")
//!    work uniformly.
//!
//! Rules that don't need cross-file context simply skip `extract`; the
//! default no-op implementation contributes nothing to the index.

pub mod flows;
pub mod generic;
pub mod registry;

use stryx_ast::ParsedFile;
use stryx_core::{Finding, RuleId, Severity};
use stryx_index::{FileSummary, ProjectIndex};

/// Per-rule metadata surfaced by `--list-rules` and reporters.
#[derive(Debug, Clone, Copy)]
pub struct RuleMeta {
    pub id: RuleId,
    pub default_severity: Severity,
    pub description: &'static str,
}

/// Context handed to a rule on every pass. The `index` is `None` during
/// the extract pass (the index is being built) and `Some` during the
/// run pass.
pub struct RuleContext<'a, 'b> {
    pub file: &'a ParsedFile<'b>,
    pub index: Option<&'a ProjectIndex>,
}

/// What a rule contributes to the project index. Most rules return
/// `None`. Cross-file rules return per-file extracted summaries that
/// the engine merges by file path.
pub type ExtractOutput = Option<FileSummary>;

/// Stryx rule. Stateless objects implementing this trait are registered
/// once at startup and shared across rayon workers.
pub trait Rule: Send + Sync {
    fn meta(&self) -> RuleMeta;

    /// Pass 1. Default: contribute nothing.
    fn extract<'a, 'b>(&self, _ctx: &RuleContext<'a, 'b>) -> ExtractOutput {
        None
    }

    /// Pass 2. Run the rule against a parsed file.
    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding>;
}

pub use registry::{RuleRegistry, builtin_rules};
