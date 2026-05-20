//! Sink-step variants (ADR 0008).
//!
//! Slice 8.4 lands [`PrismaWriteSink`], [`DrizzleWriteSink`], and
//! [`OrmWriteSink`] — the three ORM write shapes recognised by
//! [`crate::flows::unvalidated_body_to_db`]. Slice 8.4b adds
//! `ResponseSink` (the response-body sink shared with
//! `flow/secret-to-response`).
//!
//! v0.5.0-track adds three new sink families surfaced by NodeGoat/
//! DVNA dogfooding: [`eval::EvalSink`] (`eval` / `Function` /
//! `setTimeout` with string arg), [`nosql::NoSqlSink`] (MongoDB
//! collection find/update calls with body-shaped object literals),
//! and [`deserialize::DeserializeSink`] (`unserialize` / `yaml.load`
//! / `vm.runInX`). Each backs its own flow rule but the sink itself
//! is exposed here for reuse by future composite rules.

pub mod db;
pub mod deserialize;
pub mod eval;
pub mod exec;
pub mod fs;
pub mod http;
pub mod llm;
pub mod nosql;
pub mod redirect;
pub mod response;
pub mod sql;

pub use db::{
    DrizzleWriteSink, OrmWriteSink, PrismaWriteSink, is_db_write_sink, is_drizzle_write_sink,
    is_orm_write_sink, is_prisma_write_sink,
};
pub use deserialize::{DeserializeSink, is_deserialize_sink_call};
pub use eval::{EvalSink, is_eval_sink_call};
pub use exec::{ExecSink, is_exec_sink_call};
pub use fs::{FsSink, is_fs_sink_call};
pub use http::{FetchSink, is_http_sink_call};
pub use llm::{LlmPromptSink, is_llm_prompt_sink_call};
pub use nosql::{NoSqlSink, is_nosql_query_sink_call};
pub use redirect::{RedirectSink, is_redirect_sink_call};
pub use response::{ResponseSink, is_response_constructor, response_sink_label};
pub use sql::{SqlSink, is_sql_sink_call};
