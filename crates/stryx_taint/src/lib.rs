//! Cross-file taint engine. Stub for v0.0.1: defines the vocabulary
//! (labels, source/sink/sanitizer roles) so rules can declare a
//! `taint_signature` per ADR-0003. The engine itself ships in v0.1.

use serde::{Deserialize, Serialize};
use stryx_core::Span;

/// A taint label classifies *what kind of trust* flows through a value.
/// Labels are deliberately coarse — a rule reasons over labels, not over
/// raw expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaintLabel {
    /// Anything coming off the network: `req.body`, query string, headers,
    /// form data.
    UserInput,
    /// Authenticated user identity (post-auth subject).
    AuthSubject,
    /// Secret material: API keys, tokens, hashed-but-still-sensitive blobs.
    Secret,
    /// Database row content (may itself be tainted depending on writers).
    DbRow,
}

/// Where a tainted value originates. Producers populate this when seeding
/// taint at parameters, request handlers, or external calls.
pub trait Source {
    fn label(&self) -> TaintLabel;
    fn span(&self) -> &Span;
}

/// A sink is a position where a taint label is dangerous to reach.
pub trait Sink {
    fn forbids(&self) -> &[TaintLabel];
    fn span(&self) -> &Span;
}

/// A sanitizer removes one or more taint labels from values flowing through
/// it (e.g. a Zod parser strips `UserInput`).
pub trait Sanitizer {
    fn clears(&self) -> &[TaintLabel];
    fn span(&self) -> &Span;
}

/// A concrete flow from a source to a sink, optionally passing through
/// sanitizers. The engine produces these; rules consume them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    pub label: TaintLabel,
    pub source: Span,
    pub sink: Span,
    pub sanitized: bool,
}
