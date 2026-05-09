//! Layer 3 escalation. v0.0.1 only defines the trait and a no-op client;
//! a real Anthropic/OpenAI/Ollama implementation arrives in v0.1.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use stryx_core::{Confidence, Span};

/// A request to escalate an uncertain zone. The engine builds this; LLM
/// clients translate it into a provider-specific call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRequest {
    pub rule_id: String,
    pub zone: Span,
    pub source_excerpt: String,
}

/// LLM verdict on a zone. `is_finding == false` means the LLM downgraded
/// the AST suspicion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationVerdict {
    pub is_finding: bool,
    pub confidence: Confidence,
    pub message: String,
}

#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn escalate(&self, req: EscalationRequest)
        -> Result<EscalationVerdict, LlmError>;
}

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("llm escalation disabled")]
    Disabled,
    #[error("llm provider error: {0}")]
    Provider(String),
}

/// Default client used when escalation is disabled (`--no-llm`, free tier,
/// or no API key configured). Always returns [`LlmError::Disabled`].
pub struct NullLlmClient;

#[async_trait]
impl LlmClient for NullLlmClient {
    async fn escalate(
        &self,
        _req: EscalationRequest,
    ) -> Result<EscalationVerdict, LlmError> {
        Err(LlmError::Disabled)
    }
}
