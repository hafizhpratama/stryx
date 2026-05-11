//! Taint flow step substrate ([ADR 0008]).
//!
//! Each step variant recognises a fragment of taint-flow semantics —
//! a source, sink, sanitiser, or propagator — that the visitor
//! dispatches through a closed-enum registry. Rules declare their
//! applicable steps as a `&'static [StepKind]` constant; the visitor
//! asks the registry "does this expression match any source?" rather
//! than calling hardcoded predicates inline.
//!
//! Slice 8.1 of ADR 0008 — substrate-only. The trait, value types,
//! and an uninhabited [`StepKind`] enum are defined. First real
//! variant lands in slice 8.2 ([`sources::BodySource`]).
//!
//! [ADR 0008]: ../../../../docs/decisions/0008-taint-step-trait-substrate.md
//! [`sources::BodySource`]: sources

use std::path::Path;

use stryx_ast::ast::{CallExpression, Expression};
use stryx_core::Severity;
use stryx_index::ProjectIndex;
use stryx_taint::TaintLabel;

pub mod hof;
pub mod propagators;
pub mod sanitizers;
pub mod sinks;
pub mod sources;

/// Read-only context handed to every step recogniser. Carries the
/// view of state a step needs to decide whether it applies at a
/// given expression site.
///
/// Mutable visitor state (scope stack, param-shape accumulator) is
/// intentionally not exposed here — steps answer questions; the
/// visitor mutates state in response to their answers. Future
/// slices may extend this struct as new step variants need more
/// context, but adding mutability is out of scope.
pub struct StepCtx<'a, 'idx> {
    pub file: &'a Path,
    pub index: Option<&'idx ProjectIndex>,
    /// `true` when the visitor is *not* inside a validation-wrapper
    /// suppression frame. Body-source recognition is gated on this
    /// flag — see [ADR 0006] for the wrapper-suppression model.
    ///
    /// [ADR 0006]: ../../../../docs/decisions/0006-shape-lattice-taint-summary.md
    pub body_source_active: bool,
}

/// What a sink recogniser tells the visitor when it matches.
///
/// Severity is a *hint* — the consuming rule still applies its own
/// downgrade rules (e.g. Prisma `where`-only writes drop from High
/// to Medium). Sink recognition is decoupled from severity policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkSpec {
    pub severity_hint: Severity,
}

/// Kind of propagation a [`PropSpec`] describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropKind {
    /// Sub-expression taint flows into this expression as taint.
    /// Example: `body + ""` propagates `body`'s taint to the result.
    Taint,
    /// Pass-through value semantics — taint is preserved verbatim,
    /// not introduced. Example: parenthesised expression.
    Value,
}

/// What a propagator recogniser tells the visitor when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropSpec {
    pub kind: PropKind,
}

/// A taint flow step.
///
/// Each impl recognises a fragment of taint semantics — one of
/// {source, sink, sanitiser, propagator}. All four methods default
/// to no-op (return `None` / `false`); impls only override the
/// methods they actually handle. A `BodySource` step overrides
/// `as_source` only; a `PrismaWriteSink` overrides `as_sink` only;
/// most steps participate in a single role.
///
/// The trait is dispatched via [`StepKind`]'s closed-enum match —
/// no `Box<dyn TaintStep>` in the hot path
/// ([CLAUDE.md](../../../../CLAUDE.md) hard rule #3). Authoring a
/// new step means: write a struct, `impl TaintStep` for it, add a
/// variant to `StepKind`.
pub trait TaintStep {
    fn as_source(&self, _ctx: &StepCtx<'_, '_>, _expr: &Expression<'_>) -> Option<TaintLabel> {
        None
    }

    /// Kind-specialised source recogniser for call expressions. Used
    /// from contexts that already have a `&CallExpression` in hand
    /// (chain elements, sink-scan recursion) and can't ergonomically
    /// wrap it back into an [`Expression`] — `Expression::CallExpression`
    /// owns a `Box<CallExpression>` that can't be constructed from a
    /// borrowed call without cloning. Steps that participate in
    /// source recognition should ideally override either this *or*
    /// `as_source`; the default impl returns `None`.
    fn as_call_source(
        &self,
        _ctx: &StepCtx<'_, '_>,
        _call: &CallExpression<'_>,
    ) -> Option<TaintLabel> {
        None
    }

    /// Kind-specialised source recogniser for member-access
    /// expressions. Used from chain-element contexts that have only
    /// the destructured `(object, property)` pair.
    fn as_member_source(
        &self,
        _ctx: &StepCtx<'_, '_>,
        _object: &Expression<'_>,
        _prop: &str,
    ) -> Option<TaintLabel> {
        None
    }

    fn as_sink(&self, _ctx: &StepCtx<'_, '_>, _call: &CallExpression<'_>) -> Option<SinkSpec> {
        None
    }

    fn as_sanitizer(&self, _ctx: &StepCtx<'_, '_>, _call: &CallExpression<'_>) -> bool {
        false
    }

    fn as_propagator(&self, _ctx: &StepCtx<'_, '_>, _expr: &Expression<'_>) -> Option<PropSpec> {
        None
    }
}

/// Closed-enum registry of all step variants the engine knows about.
///
/// Slice 8.2 lands the first variant, [`sources::BodySource`].
/// Subsequent slices add sinks (8.4), sanitisers (8.3), and
/// propagators (8.5). The closed-enum shape keeps dispatch on the
/// hot path as a jump table — no `Box<dyn TaintStep>`
/// ([CLAUDE.md] hard rule #3).
///
/// [CLAUDE.md]: ../../../../CLAUDE.md
pub enum StepKind {
    BodySource(sources::BodySource),
    ParserSanitizer(sanitizers::ParserSanitizer),
    AuthCheckSanitizer(sanitizers::AuthCheckSanitizer),
    RedactorSanitizer(sanitizers::RedactorSanitizer),
    PrismaWriteSink(sinks::PrismaWriteSink),
    DrizzleWriteSink(sinks::DrizzleWriteSink),
    OrmWriteSink(sinks::OrmWriteSink),
    ResponseSink(sinks::ResponseSink),
    FetchSink(sinks::FetchSink),
    RedirectSink(sinks::RedirectSink),
    FsSink(sinks::FsSink),
    LlmPromptSink(sinks::LlmPromptSink),
    StructuralPropagator(propagators::StructuralPropagator),
    /// Reserved for ADR 0007 slice 3.6 — callable-shaped recogniser
    /// (producer side of HOF taint flow). Substrate-only at slice
    /// 8.7; default no-op impl.
    FunCallable(hof::FunCallable),
    /// Reserved for ADR 0007 slice 3.6 — callback-arg taint
    /// propagator (consumer side of HOF taint flow). Substrate-only
    /// at slice 8.7; default no-op impl.
    FunPropagation(hof::FunPropagation),
}

impl StepKind {
    pub fn as_source(&self, ctx: &StepCtx<'_, '_>, expr: &Expression<'_>) -> Option<TaintLabel> {
        match self {
            StepKind::BodySource(s) => s.as_source(ctx, expr),
            StepKind::ParserSanitizer(s) => s.as_source(ctx, expr),
            StepKind::AuthCheckSanitizer(s) => s.as_source(ctx, expr),
            StepKind::RedactorSanitizer(s) => s.as_source(ctx, expr),
            StepKind::PrismaWriteSink(s) => s.as_source(ctx, expr),
            StepKind::DrizzleWriteSink(s) => s.as_source(ctx, expr),
            StepKind::OrmWriteSink(s) => s.as_source(ctx, expr),
            StepKind::ResponseSink(s) => s.as_source(ctx, expr),
            StepKind::FetchSink(s) => s.as_source(ctx, expr),
            StepKind::RedirectSink(s) => s.as_source(ctx, expr),
            StepKind::FsSink(s) => s.as_source(ctx, expr),
            StepKind::LlmPromptSink(s) => s.as_source(ctx, expr),
            StepKind::StructuralPropagator(s) => s.as_source(ctx, expr),
            StepKind::FunCallable(s) => s.as_source(ctx, expr),
            StepKind::FunPropagation(s) => s.as_source(ctx, expr),
        }
    }

    pub fn as_call_source(
        &self,
        ctx: &StepCtx<'_, '_>,
        call: &CallExpression<'_>,
    ) -> Option<TaintLabel> {
        match self {
            StepKind::BodySource(s) => s.as_call_source(ctx, call),
            StepKind::ParserSanitizer(s) => s.as_call_source(ctx, call),
            StepKind::AuthCheckSanitizer(s) => s.as_call_source(ctx, call),
            StepKind::RedactorSanitizer(s) => s.as_call_source(ctx, call),
            StepKind::PrismaWriteSink(s) => s.as_call_source(ctx, call),
            StepKind::DrizzleWriteSink(s) => s.as_call_source(ctx, call),
            StepKind::OrmWriteSink(s) => s.as_call_source(ctx, call),
            StepKind::ResponseSink(s) => s.as_call_source(ctx, call),
            StepKind::FetchSink(s) => s.as_call_source(ctx, call),
            StepKind::RedirectSink(s) => s.as_call_source(ctx, call),
            StepKind::FsSink(s) => s.as_call_source(ctx, call),
            StepKind::LlmPromptSink(s) => s.as_call_source(ctx, call),
            StepKind::StructuralPropagator(s) => s.as_call_source(ctx, call),
            StepKind::FunCallable(s) => s.as_call_source(ctx, call),
            StepKind::FunPropagation(s) => s.as_call_source(ctx, call),
        }
    }

    pub fn as_member_source(
        &self,
        ctx: &StepCtx<'_, '_>,
        object: &Expression<'_>,
        prop: &str,
    ) -> Option<TaintLabel> {
        match self {
            StepKind::BodySource(s) => s.as_member_source(ctx, object, prop),
            StepKind::ParserSanitizer(s) => s.as_member_source(ctx, object, prop),
            StepKind::AuthCheckSanitizer(s) => s.as_member_source(ctx, object, prop),
            StepKind::RedactorSanitizer(s) => s.as_member_source(ctx, object, prop),
            StepKind::PrismaWriteSink(s) => s.as_member_source(ctx, object, prop),
            StepKind::DrizzleWriteSink(s) => s.as_member_source(ctx, object, prop),
            StepKind::OrmWriteSink(s) => s.as_member_source(ctx, object, prop),
            StepKind::ResponseSink(s) => s.as_member_source(ctx, object, prop),
            StepKind::FetchSink(s) => s.as_member_source(ctx, object, prop),
            StepKind::RedirectSink(s) => s.as_member_source(ctx, object, prop),
            StepKind::FsSink(s) => s.as_member_source(ctx, object, prop),
            StepKind::LlmPromptSink(s) => s.as_member_source(ctx, object, prop),
            StepKind::StructuralPropagator(s) => s.as_member_source(ctx, object, prop),
            StepKind::FunCallable(s) => s.as_member_source(ctx, object, prop),
            StepKind::FunPropagation(s) => s.as_member_source(ctx, object, prop),
        }
    }

    pub fn as_sink(&self, ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> Option<SinkSpec> {
        match self {
            StepKind::BodySource(s) => s.as_sink(ctx, call),
            StepKind::ParserSanitizer(s) => s.as_sink(ctx, call),
            StepKind::AuthCheckSanitizer(s) => s.as_sink(ctx, call),
            StepKind::RedactorSanitizer(s) => s.as_sink(ctx, call),
            StepKind::PrismaWriteSink(s) => s.as_sink(ctx, call),
            StepKind::DrizzleWriteSink(s) => s.as_sink(ctx, call),
            StepKind::OrmWriteSink(s) => s.as_sink(ctx, call),
            StepKind::ResponseSink(s) => s.as_sink(ctx, call),
            StepKind::FetchSink(s) => s.as_sink(ctx, call),
            StepKind::RedirectSink(s) => s.as_sink(ctx, call),
            StepKind::FsSink(s) => s.as_sink(ctx, call),
            StepKind::LlmPromptSink(s) => s.as_sink(ctx, call),
            StepKind::StructuralPropagator(s) => s.as_sink(ctx, call),
            StepKind::FunCallable(s) => s.as_sink(ctx, call),
            StepKind::FunPropagation(s) => s.as_sink(ctx, call),
        }
    }

    pub fn as_sanitizer(&self, ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> bool {
        match self {
            StepKind::BodySource(s) => s.as_sanitizer(ctx, call),
            StepKind::ParserSanitizer(s) => s.as_sanitizer(ctx, call),
            StepKind::AuthCheckSanitizer(s) => s.as_sanitizer(ctx, call),
            StepKind::RedactorSanitizer(s) => s.as_sanitizer(ctx, call),
            StepKind::PrismaWriteSink(s) => s.as_sanitizer(ctx, call),
            StepKind::DrizzleWriteSink(s) => s.as_sanitizer(ctx, call),
            StepKind::OrmWriteSink(s) => s.as_sanitizer(ctx, call),
            StepKind::ResponseSink(s) => s.as_sanitizer(ctx, call),
            StepKind::FetchSink(s) => s.as_sanitizer(ctx, call),
            StepKind::RedirectSink(s) => s.as_sanitizer(ctx, call),
            StepKind::FsSink(s) => s.as_sanitizer(ctx, call),
            StepKind::LlmPromptSink(s) => s.as_sanitizer(ctx, call),
            StepKind::StructuralPropagator(s) => s.as_sanitizer(ctx, call),
            StepKind::FunCallable(s) => s.as_sanitizer(ctx, call),
            StepKind::FunPropagation(s) => s.as_sanitizer(ctx, call),
        }
    }

    pub fn as_propagator(&self, ctx: &StepCtx<'_, '_>, expr: &Expression<'_>) -> Option<PropSpec> {
        match self {
            StepKind::BodySource(s) => s.as_propagator(ctx, expr),
            StepKind::ParserSanitizer(s) => s.as_propagator(ctx, expr),
            StepKind::AuthCheckSanitizer(s) => s.as_propagator(ctx, expr),
            StepKind::RedactorSanitizer(s) => s.as_propagator(ctx, expr),
            StepKind::PrismaWriteSink(s) => s.as_propagator(ctx, expr),
            StepKind::DrizzleWriteSink(s) => s.as_propagator(ctx, expr),
            StepKind::OrmWriteSink(s) => s.as_propagator(ctx, expr),
            StepKind::ResponseSink(s) => s.as_propagator(ctx, expr),
            StepKind::FetchSink(s) => s.as_propagator(ctx, expr),
            StepKind::RedirectSink(s) => s.as_propagator(ctx, expr),
            StepKind::FsSink(s) => s.as_propagator(ctx, expr),
            StepKind::LlmPromptSink(s) => s.as_propagator(ctx, expr),
            StepKind::StructuralPropagator(s) => s.as_propagator(ctx, expr),
            StepKind::FunCallable(s) => s.as_propagator(ctx, expr),
            StepKind::FunPropagation(s) => s.as_propagator(ctx, expr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Concrete impl with all defaults — proves the default methods
    /// compile and return the no-op values.
    struct AllDefaults;
    impl TaintStep for AllDefaults {}

    fn ctx() -> StepCtx<'static, 'static> {
        StepCtx {
            file: Path::new("/dev/null"),
            index: None,
            body_source_active: true,
        }
    }

    /// `as_source` defaults to `None`. We can't easily construct an
    /// `Expression<'_>` without a parsed AST here, so we exercise
    /// the trait surface via a test that doesn't materialise a real
    /// expression — the call site type-checks the signature, which
    /// is the contract slice 8.1 establishes.
    #[test]
    fn default_impls_match_substrate_contract() {
        let _ = AllDefaults;
        let _ = ctx();
        // The substantive checks (default = None / false on real
        // expressions) land at slice 8.2 with the first variant,
        // which gives us a real Expression to pass.
    }

    #[test]
    fn sink_and_prop_specs_round_trip() {
        let s = SinkSpec {
            severity_hint: Severity::High,
        };
        assert_eq!(s.severity_hint, Severity::High);

        let p = PropSpec {
            kind: PropKind::Taint,
        };
        assert_eq!(p.kind, PropKind::Taint);

        let v = PropSpec {
            kind: PropKind::Value,
        };
        assert_ne!(v.kind, p.kind);
    }
}
