//! [`StructuralPropagator`] — closed-set classifier for the
//! expression kinds whose taint is determined by recursing on
//! their structural sub-expressions ([ADR 0008] slice 8.5).
//!
//! Propagators differ from sources/sinks/sanitisers in that they
//! don't pattern-match against a call name or member shape — they
//! match against the *expression kind* (binary, template, ternary,
//! object/array literal, paren, cast, …). Every kind below carries
//! taint when any of its sub-expressions does.
//!
//! The actual recursion stays inside the visitor: steps can't reach
//! visitor state (scopes, identifier tables), and the recursion is
//! the visitor's job. This step's role is to publish the *closed
//! set* of propagator shapes in one place, so the visitor can
//! parallel-assert agreement and future propagator-shaped additions
//! (e.g. a framework-specific AST node) gain registry membership in
//! the same edit.
//!
//! [ADR 0008]: ../../../../../docs/decisions/0008-taint-step-trait-substrate.md

use stryx_ast::ast::Expression;

use crate::steps::{PropKind, PropSpec, StepCtx, TaintStep};

/// Recognises the closed set of structural-taint propagator
/// expression shapes (see module docs).
pub struct StructuralPropagator;

impl TaintStep for StructuralPropagator {
    fn as_propagator(&self, _ctx: &StepCtx<'_, '_>, expr: &Expression<'_>) -> Option<PropSpec> {
        if is_structural_propagator(expr) {
            Some(PropSpec {
                kind: PropKind::Taint,
            })
        } else {
            None
        }
    }
}

/// True iff `expr` is one of the AST shapes whose taint is the
/// disjunction of its sub-expressions' taint. Must stay in sync
/// with the corresponding match arms in
/// `flows::unvalidated_body_to_db::FlowVisitor::expr_taint` —
/// the visitor parallel-asserts agreement in debug builds.
pub fn is_structural_propagator(expr: &Expression<'_>) -> bool {
    matches!(
        expr,
        // Unwrap shapes — single inner expression.
        Expression::AwaitExpression(_)
        | Expression::ParenthesizedExpression(_)
        | Expression::TSAsExpression(_)
        | Expression::TSNonNullExpression(_)
        | Expression::TSSatisfiesExpression(_)
        | Expression::TSTypeAssertion(_)
        // Optional-chain wrapper — propagates from inner chain element.
        | Expression::ChainExpression(_)
        // Member access — propagates from `.object`. Static member
        // expressions are ALSO checked for body-source shape before
        // this propagator role fires; both classifications are valid
        // (a body source is also a propagator shape — the visitor
        // simply short-circuits with the source result).
        | Expression::StaticMemberExpression(_)
        | Expression::ComputedMemberExpression(_)
        | Expression::PrivateFieldExpression(_)
        // Aggregate shapes — taint via any sub-expression.
        | Expression::ObjectExpression(_)
        | Expression::ArrayExpression(_)
        | Expression::TemplateLiteral(_)
        | Expression::TaggedTemplateExpression(_)
        | Expression::ConditionalExpression(_)
        | Expression::LogicalExpression(_)
        | Expression::BinaryExpression(_),
    )
}
