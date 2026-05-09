use crate::{RuleId, Severity, Span};
use serde::{Deserialize, Serialize};

/// Confidence in a finding. Always 1.0 for AST-derived findings; only LLM
/// escalations produce values below 1.0.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Confidence(pub f32);

impl Confidence {
    pub const CERTAIN: Self = Self(1.0);

    pub fn new(value: f32) -> Self {
        Self(value.clamp(0.0, 1.0))
    }
}

/// Where a finding came from. Reporters surface this so users know whether
/// an issue is deterministic AST evidence or an LLM judgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSource {
    Ast,
    Llm,
}

/// A single rule violation against real code. The wire format here is part
/// of the public CLI contract — see `docs/architecture/rule-format.md`.
///
/// `rule_id` is owned (`String`) on the wire so the JSON reporter can
/// round-trip findings; rule code declares ids as `RuleId` (`&'static str`)
/// and they're upgraded here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    pub span: Span,
    pub source: FindingSource,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
}

impl Finding {
    pub fn ast(
        rule_id: RuleId,
        severity: Severity,
        message: impl Into<String>,
        span: Span,
    ) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            severity,
            message: message.into(),
            span,
            source: FindingSource::Ast,
            confidence: Confidence::CERTAIN,
            help: None,
        }
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }
}
