//! Sink-step variants (ADR 0008).
//!
//! Slice 8.4 lands [`PrismaWriteSink`], [`DrizzleWriteSink`], and
//! [`OrmWriteSink`] — the three ORM write shapes recognised by
//! [`crate::flows::unvalidated_body_to_db`]. Slice 8.4b adds
//! `ResponseSink` (the response-body sink shared with
//! `flow/secret-to-response`).

pub mod db;
pub mod response;

pub use db::{
    DrizzleWriteSink, OrmWriteSink, PrismaWriteSink, is_db_write_sink, is_drizzle_write_sink,
    is_orm_write_sink, is_prisma_write_sink,
};
pub use response::{ResponseSink, is_response_constructor, response_sink_label};
