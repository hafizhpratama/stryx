//! Core types for Stryx. No analyzer logic lives here — only the vocabulary
//! every other crate speaks: severities, spans, findings, rule identity.

pub mod finding;
pub mod severity;
pub mod span;

pub use finding::{Confidence, Finding, FindingSource};
pub use severity::Severity;
pub use span::{ByteOffset, Span};

/// Stable identifier for a rule, e.g. `"generic/hardcoded-secret"`.
///
/// Rule IDs are a public contract: changing one is a breaking change. See
/// `docs/architecture/rule-format.md`.
pub type RuleId = &'static str;

/// Fatal errors surfaced by the engine. Library code returns these; the
/// binary maps them to exit codes.
#[derive(Debug, thiserror::Error)]
pub enum StryxError {
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("parse error in {path}: {message}")]
    Parse { path: String, message: String },

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, StryxError>;
