//! LLM-prompt sink step — recognises the OpenAI / Anthropic SDK
//! call shapes that send a prompt to a provider. Used by
//! `flow/prompt-injection`.
//!
//! Recognised shapes (the receiver expression is opaque — any
//! identifier resolves; in practice the user has an `openai` or
//! `anthropic` instance, sometimes wrapped via a default-exported
//! factory):
//!
//! - `<x>.chat.completions.create(...)` — the canonical OpenAI
//!   chat-completion shape.
//! - `<x>.responses.create(...)` — OpenAI's newer Responses API.
//! - `<x>.messages.create(...)` — Anthropic's chat-completion
//!   shape.
//!
//! The recogniser is path-shape only — it does not consult an
//! import map. The intent is that any callee whose method path
//! exactly matches one of the three patterns is an LLM-prompt
//! sink. False positives from non-LLM SDKs that happen to expose
//! `.chat.completions.create` or `.messages.create` are vanishingly
//! rare in practice (the path-shape is provider-specific).
//!
//! Severity hint is `High` — prompt injection is OWASP LLM01 and
//! the consequences (data exfiltration, instruction override, tool
//! abuse) are uniformly high-impact for any LLM-backed product.

use stryx_ast::ast::{CallExpression, Expression, MemberExpression};
use stryx_core::Severity;

use crate::steps::{SinkSpec, StepCtx, TaintStep};

/// LLM-prompt sink recogniser. Stateless; [`StepCtx`] is unused.
#[derive(Debug, Default, Clone, Copy)]
pub struct LlmPromptSink;

impl TaintStep for LlmPromptSink {
    fn as_sink(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> Option<SinkSpec> {
        if is_llm_prompt_sink_call(call) {
            Some(SinkSpec {
                severity_hint: Severity::High,
            })
        } else {
            None
        }
    }
}

/// True iff `call` is one of the recognised LLM SDK shapes:
/// `<x>.chat.completions.create(...)`, `<x>.responses.create(...)`,
/// or `<x>.messages.create(...)`. Provider-specific shapes —
/// `chat.completions` and `responses` are OpenAI; `messages` is
/// Anthropic.
pub fn is_llm_prompt_sink_call(call: &CallExpression<'_>) -> bool {
    let Some(MemberExpression::StaticMemberExpression(method)) = call.callee.as_member_expression()
    else {
        return false;
    };
    if method.property.name != "create" {
        return false;
    }
    // The receiver of `.create(...)` must be a static member access.
    // Inspect its property name to classify:
    //   `<x>.responses.create(...)`     — `responses`
    //   `<x>.messages.create(...)`      — `messages`
    //   `<x>.completions.create(...)`   — `completions` + receiver
    //                                     must end in `.chat`
    let Expression::StaticMemberExpression(receiver) = &method.object else {
        return false;
    };
    match receiver.property.name.as_str() {
        "responses" | "messages" => true,
        "completions" => {
            let Expression::StaticMemberExpression(chat) = &receiver.object else {
                return false;
            };
            chat.property.name == "chat"
        }
        _ => false,
    }
}
