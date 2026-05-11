//! Sink-step variants (ADR 0008).
//!
//! Substrate-only at slice 8.1. Variants land at slice 8.4 —
//! `PrismaWriteSink`, `DrizzleWriteSink`, `OrmWriteSink`,
//! `ResponseSink`. The duplicated-across-rules `ResponseSink`
//! (currently in both [`crate::flows::unvalidated_body_to_db`] and
//! [`crate::flows::secret_to_response`]) becomes a single canonical
//! step at the migration.
