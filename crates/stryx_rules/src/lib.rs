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

pub mod adapters;
pub mod adapters_ajv;
pub mod adapters_anthropic;
pub mod adapters_auth_js;
pub mod adapters_better_auth;
pub mod adapters_bun;
pub mod adapters_class_validator;
pub mod adapters_clerk;
pub mod adapters_drizzle;
pub mod adapters_express;
pub mod adapters_fastify;
pub mod adapters_hono;
pub mod adapters_joi;
pub mod adapters_mysql2;
pub mod adapters_nestjs;
pub mod adapters_next;
pub mod adapters_node;
pub mod adapters_openai;
pub mod adapters_pg;
pub mod adapters_prisma;
pub mod adapters_valibot;
pub mod adapters_yup;
pub mod adapters_zod;
pub mod flows;
pub mod generic;
pub mod registry;
pub mod steps;

use stryx_ast::ParsedFile;
use stryx_ast::ast::Expression;
use stryx_core::{Finding, RuleId, Severity};
use stryx_index::{FileSummary, ProjectIndex};

use crate::adapters::{
    EnabledAdapters, GuardPattern, MatcherContext, PropagatorPattern, SanitiserPattern,
    SinkPattern, SourcePattern,
};

/// Per-rule metadata surfaced by `--list-rules` and reporters.
#[derive(Debug, Clone, Copy)]
pub struct RuleMeta {
    pub id: RuleId,
    pub default_severity: Severity,
    pub description: &'static str,
}

/// Context handed to a rule on every pass. The `index` is `None` during
/// the extract pass (the index is being built) and `Some` during the
/// run pass. `adapters` is `None` when the caller hasn't resolved a
/// `ProjectProfile` yet (most unit-test sites); production scans
/// always populate it from
/// [`adapters::AdapterRegistry::enabled_for`].
pub struct RuleContext<'a, 'b> {
    pub file: &'a ParsedFile<'b>,
    pub index: Option<&'a ProjectIndex>,
    pub adapters: Option<&'a EnabledAdapters>,
}

impl<'a, 'b> RuleContext<'a, 'b> {
    /// First source pattern in the enabled adapter set whose matcher
    /// list matches `expr`. Returns `None` when no adapters are
    /// configured (`self.adapters` is `None`), when none of the
    /// active adapters contribute sources, or when no matcher fires.
    ///
    /// Rule callers use this to ask "is this expression a recognised
    /// untrusted-input source on the active stack?" without knowing
    /// which adapters are live. The returned pattern's `label` drives
    /// the taint label introduced; `id` is the diagnostic attribution
    /// used by reporters (`source: framework/nestjs/body-param`).
    pub fn match_source(&self, expr: &Expression<'_>) -> Option<&'static SourcePattern> {
        let mctx = MatcherContext {
            file: self.file,
            index: self.index,
        };
        self.adapters?
            .sources
            .iter()
            .find(|p| p.matchers.iter().any(|m| m.matches(&mctx, expr)))
            .copied()
    }

    /// First sink pattern whose matcher list matches `expr`. See
    /// [`match_source`](Self::match_source) for the lookup model.
    pub fn match_sink(&self, expr: &Expression<'_>) -> Option<&'static SinkPattern> {
        let mctx = MatcherContext {
            file: self.file,
            index: self.index,
        };
        self.adapters?
            .sinks
            .iter()
            .find(|p| p.matchers.iter().any(|m| m.matches(&mctx, expr)))
            .copied()
    }

    /// First sanitiser pattern whose matcher list matches `expr`. See
    /// [`match_source`](Self::match_source) for the lookup model.
    pub fn match_sanitiser(&self, expr: &Expression<'_>) -> Option<&'static SanitiserPattern> {
        let mctx = MatcherContext {
            file: self.file,
            index: self.index,
        };
        self.adapters?
            .sanitisers
            .iter()
            .find(|p| p.matchers.iter().any(|m| m.matches(&mctx, expr)))
            .copied()
    }

    /// First guard pattern whose matcher list matches `expr`. See
    /// [`match_source`](Self::match_source) for the lookup model.
    pub fn match_guard(&self, expr: &Expression<'_>) -> Option<&'static GuardPattern> {
        let mctx = MatcherContext {
            file: self.file,
            index: self.index,
        };
        self.adapters?
            .guards
            .iter()
            .find(|p| p.matchers.iter().any(|m| m.matches(&mctx, expr)))
            .copied()
    }

    /// First propagator pattern whose matcher list matches `expr`. See
    /// [`match_source`](Self::match_source) for the lookup model.
    pub fn match_propagator(&self, expr: &Expression<'_>) -> Option<&'static PropagatorPattern> {
        let mctx = MatcherContext {
            file: self.file,
            index: self.index,
        };
        self.adapters?
            .propagators
            .iter()
            .find(|p| p.matchers.iter().any(|m| m.matches(&mctx, expr)))
            .copied()
    }
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

#[cfg(test)]
mod context_tests {
    //! Wiring tests for the adapter substrate hook on
    //! [`RuleContext`]. They guard the *plumbing*: that `match_*`
    //! short-circuits to `None` when no adapters are configured, and
    //! that an `EnabledAdapters` carrying a matching pattern is
    //! actually reachable through the helper (the helper must build
    //! a [`MatcherContext`], iterate `adapters.sources`, and surface
    //! the `&'static SourcePattern` whose matcher fires).
    //!
    //! Per-variant matcher logic lives in
    //! [`crate::adapters::AstMatcher::matches`]; this module only
    //! pins the wiring, so a single matcher variant is sufficient to
    //! prove the round-trip.
    use super::*;
    use crate::adapters::{AstMatcher, EnabledAdapters, SourcePattern};
    use std::path::Path;
    use stryx_ast::{Allocator, parse};
    use stryx_taint::TaintLabel;

    /// Minimal expression source — `req.body` is the canonical
    /// `MemberOnParam` shape and the only matcher variant we exercise
    /// here. Wiring tests deliberately do not enumerate variants;
    /// matcher-variant coverage belongs in `adapters.rs`.
    const SAMPLE: &str = "const x = req.body;";

    fn first_expression<'a>(parsed: &'a stryx_ast::ParsedFile<'_>) -> &'a Expression<'a> {
        // `const x = <expr>;` parses to one VariableDeclaration with
        // exactly one declarator whose `init` is the expression we
        // want. Anything else is a fixture bug, so panic loudly.
        use stryx_ast::ast::Statement;
        let stmt = parsed
            .program
            .body
            .first()
            .expect("sample has one statement");
        match stmt {
            Statement::VariableDeclaration(decl) => decl
                .declarations
                .first()
                .and_then(|d| d.init.as_ref())
                .expect("declarator with init"),
            _ => panic!("sample must parse to a VariableDeclaration"),
        }
    }

    #[test]
    fn match_source_returns_none_when_no_adapters_configured() {
        let allocator = Allocator::default();
        let parsed = parse(&allocator, Path::new("/virt/file.ts"), SAMPLE).expect("parse");
        let expr = first_expression(&parsed);

        let ctx = RuleContext {
            file: &parsed,
            index: None,
            adapters: None,
        };

        assert!(
            ctx.match_source(expr).is_none(),
            "with `adapters: None`, match_source must short-circuit to None"
        );
    }

    #[test]
    fn match_source_returns_pattern_when_matcher_fires() {
        // Wiring round-trip: an EnabledAdapters carrying a
        // SourcePattern whose `MemberOnParam` matcher targets
        // `req.body` is reachable through `ctx.match_source`, and the
        // helper surfaces the same `&'static SourcePattern` reference
        // back to the caller (preserving `id` and `label` so rules
        // can attribute and propagate correctly).
        static MATCHERS: &[AstMatcher] = &[AstMatcher::MemberOnParam {
            receiver: "req",
            property: "body",
        }];
        static PATTERN: SourcePattern = SourcePattern {
            id: "test/req-body",
            label: TaintLabel::UserInput,
            matchers: MATCHERS,
        };
        let enabled = EnabledAdapters {
            active: Vec::new(),
            sources: vec![&PATTERN],
            sinks: Vec::new(),
            sanitisers: Vec::new(),
            guards: Vec::new(),
            propagators: Vec::new(),
        };

        let allocator = Allocator::default();
        let parsed = parse(&allocator, Path::new("/virt/file.ts"), SAMPLE).expect("parse");
        let expr = first_expression(&parsed);

        let ctx = RuleContext {
            file: &parsed,
            index: None,
            adapters: Some(&enabled),
        };

        let matched = ctx
            .match_source(expr)
            .expect("matcher recognises `req.body`; helper must surface the pattern");
        assert_eq!(matched.id, "test/req-body");
        assert_eq!(matched.label, TaintLabel::UserInput);
    }
}
