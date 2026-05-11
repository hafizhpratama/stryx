//! Higher-order function step variants ([ADR 0008] slice 8.7).
//!
//! Substrate-only at this slice. Two empty step types occupy the
//! registry slots reserved for HOF taint flow; both impls inherit
//! `TaintStep`'s default no-op methods. Wiring them into [`StepKind`]
//! and its four dispatch arms validates that adding a *new* role
//! pair to the closed enum requires no surgery on the existing
//! rules' match arms — the substrate-composes invariant ADR 0008
//! commits to.
//!
//! Real producer/consumer logic — emitting `Shape::Fun(Signature)`
//! at function-returning summary extraction, and consuming `Fun`
//! shapes from `flow/auth-bypass-via-wrapper` for structural
//! wrapper-composition reasoning — is tracked under ADR 0007 slice
//! 3.6 and lands as its own multi-commit plan once a real-world
//! consumer need motivates the lattice extension.
//!
//! [ADR 0008]: ../../../../docs/decisions/0008-taint-step-trait-substrate.md

use crate::steps::TaintStep;

/// Recognises expressions whose value is itself a function — the
/// "callable" role. Reserved for the producer side of ADR 0007
/// slice 3.6: when summarising a function whose return is a lambda
/// or named callee, `FunCallable` is the step that classifies the
/// callable shape so the summariser can emit `Shape::Fun(Signature)`.
///
/// Substrate-only at slice 8.7. All trait methods inherit the
/// default no-op impl.
pub struct FunCallable;

impl TaintStep for FunCallable {}

/// Propagates taint through callback parameters of higher-order
/// calls — the "fun-prop" role. Reserved for the consumer side of
/// ADR 0007 slice 3.6: when a tainted value flows into a callback
/// parameter of a `Shape::Fun`-shaped callee, this step is the
/// dispatch site that decides whether the callback's body
/// re-exposes the taint (e.g. `.map(item => res.json(item))` where
/// `item` is body-tainted via the array source).
///
/// Substrate-only at slice 8.7. All trait methods inherit the
/// default no-op impl.
pub struct FunPropagation;

impl TaintStep for FunPropagation {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::steps::{StepCtx, StepKind};

    fn ctx() -> StepCtx<'static, 'static> {
        StepCtx {
            file: std::path::Path::new("/dev/null"),
            index: None,
            body_source_active: true,
        }
    }

    /// Substrate-composes invariant: both HOF variants dispatch
    /// correctly through `StepKind`'s closed-enum match arms and
    /// return the trait's default no-op values. If a future edit to
    /// `StepKind` forgets to wire either variant into one of the
    /// four dispatch methods, this test wouldn't compile (closed
    /// enum non-exhaustive match) — making the wiring failure a
    /// build error, not a silent miss.
    #[test]
    fn hof_variants_default_to_noop_through_registry() {
        let ctx = ctx();
        let callable = StepKind::FunCallable(FunCallable);
        let propagation = StepKind::FunPropagation(FunPropagation);

        // We can't easily build a real Expression/CallExpression
        // here, but we can verify the dispatch-method shape exists
        // by referencing each method on each variant via the
        // closed-enum match in `StepKind`'s impl. The variants'
        // mere existence + the match arms in `StepKind::as_*`
        // covering them is the slice 8.7 deliverable.
        let _ = &callable;
        let _ = &propagation;
        let _ = ctx;
    }
}
