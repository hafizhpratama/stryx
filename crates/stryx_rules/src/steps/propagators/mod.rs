//! Propagator-step variants (ADR 0008 slice 8.5).
//!
//! Propagators classify the expression kinds whose taint flows
//! structurally from their sub-expressions. Slice 8.5 lands one
//! variant — [`StructuralPropagator`] — that publishes the closed
//! set in a single place. Later slices may decompose into
//! framework-specific propagators (e.g. for custom AST nodes) by
//! adding new variants alongside this one.

mod structural;

pub use structural::{StructuralPropagator, is_structural_propagator};
