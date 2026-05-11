//! Source-step variants (ADR 0008).
//!
//! Slice 8.2 lands [`BodySource`] — request-body recognition across
//! Next.js (`req.body`, `req.json()`) and Hono (`c.req.json()`)
//! shapes. Future slices add env-var sources, network-response
//! sources, and untrusted-config sources.

pub mod body;

pub use body::{BodySource, is_body_source_call, is_request_body_member};
