//! Source-step variants (ADR 0008).
//!
//! Substrate-only at slice 8.1. The first variant — `BodySource`,
//! recognising `req.body` / `req.json()` / `c.req.json()` shapes —
//! lands at slice 8.2 as the first migration target from
//! [`crate::flows::unvalidated_body_to_db`].
