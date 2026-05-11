//! Propagator-step variants (ADR 0008).
//!
//! Substrate-only at slice 8.1. Variants land at slice 8.5 — the
//! bulk of [`crate::flows::unvalidated_body_to_db::FlowVisitor::expr_taint`]
//! match arms (binary `+`, template literals, ternary, logical,
//! object/array literals, spreads, casts) become propagator step
//! variants here.
