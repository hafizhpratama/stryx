//! `llm/anthropic` adapter — Anthropic SDK prompt-creation surfaces.
//!
//! Anthropic (Claude) is the second most-deployed LLM SDK in TypeScript
//! backends after OpenAI. Its prompt-creation calls drive
//! `flow/prompt-injection`. This adapter mirrors the call shapes the
//! inline recogniser in
//! [`crate::steps::sinks::llm::is_llm_prompt_sink_call`] already matches
//! (`<x>.messages.create`, `<x>.messages.stream`), re-expressed as
//! substrate patterns so rule migration is byte-equivalent.
//!
//! ## Sinks
//!
//! Both Anthropic prompt entry points carry `SinkKind::LlmPrompt` with
//! `Severity::High` — prompt injection is OWASP LLM01 and the
//! consequences (instruction override, tool abuse, data exfiltration)
//! are uniformly high-impact for any LLM-backed product. The severity
//! floor matches the `severity_hint` returned by the existing
//! `LlmPromptSink` step.
//!
//! Two pattern IDs are exposed, one per Anthropic API surface:
//!
//! - `llm/anthropic/messages-create` —
//!   `<x>.messages.create({ messages: [...] })`, the canonical Messages
//!   API. The dominant Anthropic shape in production TypeScript
//!   backends.
//! - `llm/anthropic/messages-stream` —
//!   `<x>.messages.stream({ messages: [...] })`, the streaming variant.
//!   Same prompt-injection surface; users frequently swap between
//!   `create` and `stream` without changing the prompt path.
//!
//! ## Receiver-name limitation
//!
//! The substrate's [`AstMatcher::MethodCall`] requires a literal dotted
//! receiver chain — there is no "method-chain whose tail matches X"
//! matcher in the current variant set. The inline recogniser accepts
//! *any* receiver expression because the path shape itself
//! (`.messages.create`, `.messages.stream`) is provider-specific enough
//! that false positives are vanishingly rare.
//!
//! Bridging that gap without adding a new `AstMatcher` variant — and
//! matching the [`crate::adapters_openai::OpenAiAdapter`] approach
//! exactly so the two adapters behave symmetrically — each API surface
//! registers two receiver variants in a single pattern: `anthropic.*`
//! (the SDK's documented binding name, e.g.
//! `const anthropic = new Anthropic()`) and `client.*` (the near-
//! universal alternative, e.g. `const client = new Anthropic()`).
//! Both matchers live under one `SinkPattern` so a finding is
//! attributed to the *API surface* (Messages create vs Messages stream),
//! not to which binding name happened to match. Other binding names
//! (`claude`, `ai`, branded names) are intentionally out of scope at
//! the adapter layer; the inline recogniser still covers them until
//! rules consume `ctx.match_sink` and the substrate gains a trailing-
//! chain matcher.
//!
//! ## Activation
//!
//! Default `is_enabled` — active when the project profile contains an
//! `LlmSdkHint::Anthropic` entry at confidence ≥
//! [`crate::adapters::ENABLE_CONFIDENCE_FLOOR`] (`0.60`). The profile
//! crate serialises `Anthropic` as `"anthropic"` (per the brand-name
//! lock-in in [`stryx_index::profile`]), which matches the `anthropic`
//! suffix in this adapter's `llm/anthropic` ID. A project on OpenAI
//! (`LlmSdkHint::OpenAi`) must not activate this adapter even at high
//! confidence — adapter activation is per-name, not per-kind.

use crate::adapters::{AdapterId, AdapterKind, AstMatcher, SinkKind, SinkPattern, StackAdapter};
use stryx_core::Severity;

pub struct AnthropicAdapter;

// =============================================================================
// Sink patterns — Anthropic prompt-creation surfaces
// =============================================================================
//
// One `SinkPattern` per API surface. Each pattern lists the two
// receiver-name variants (`anthropic.*`, `client.*`) it should fire on;
// the substrate evaluates matchers as a union so either receiver match
// activates the pattern.

static SINKS: &[SinkPattern] = &[
    // Messages API (create) — the canonical Anthropic shape.
    // `<x>.messages.create({ messages: [...] })`.
    SinkPattern {
        id: "llm/anthropic/messages-create",
        sink: SinkKind::LlmPrompt,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "anthropic.messages",
                method: "create",
            },
            AstMatcher::MethodCall {
                receiver: "client.messages",
                method: "create",
            },
        ],
        severity_floor: Severity::High,
    },
    // Messages API (stream) — streaming variant of the same surface.
    // `<x>.messages.stream({ messages: [...] })`.
    SinkPattern {
        id: "llm/anthropic/messages-stream",
        sink: SinkKind::LlmPrompt,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "anthropic.messages",
                method: "stream",
            },
            AstMatcher::MethodCall {
                receiver: "client.messages",
                method: "stream",
            },
        ],
        severity_floor: Severity::High,
    },
];

impl StackAdapter for AnthropicAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("llm/anthropic")
    }
    fn kind(&self) -> AdapterKind {
        AdapterKind::LlmSdk
    }
    fn sinks(&self) -> &'static [SinkPattern] {
        SINKS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stryx_index::profile::{Detected, LlmSdkHint, ProjectProfile};

    #[test]
    fn anthropic_adapter_exposes_expected_sink_patterns() {
        let sinks = AnthropicAdapter.sinks();
        assert_eq!(sinks.len(), 2);
        let ids: Vec<&str> = sinks.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"llm/anthropic/messages-create"));
        assert!(ids.contains(&"llm/anthropic/messages-stream"));

        // Every Anthropic sink pattern carries the `LlmPrompt` semantic
        // category — the prompt-injection rule keys off `SinkKind`, not
        // the pattern ID, so any drift here would silently break
        // `flow/prompt-injection`.
        for pattern in sinks {
            assert_eq!(
                pattern.sink,
                SinkKind::LlmPrompt,
                "sink kind mismatch on {}",
                pattern.id
            );
        }
    }

    #[test]
    fn anthropic_adapter_is_llm_sdk_kind() {
        assert_eq!(AnthropicAdapter.kind(), AdapterKind::LlmSdk);
        assert_eq!(AnthropicAdapter.id(), AdapterId("llm/anthropic"));
    }

    #[test]
    fn anthropic_sinks_floor_at_high() {
        // Prompt injection is OWASP LLM01 — the floor matches the
        // `Severity::High` hint returned by the existing
        // `LlmPromptSink` step (see
        // `crate::steps::sinks::llm::LlmPromptSink::as_sink`). The
        // rule is free to raise but not lower this for specific
        // findings.
        for sink in AnthropicAdapter.sinks() {
            assert_eq!(
                sink.severity_floor,
                Severity::High,
                "LLM-prompt sink {} should floor at High",
                sink.id
            );
        }
    }

    #[test]
    fn is_enabled_returns_true_under_anthropic_profile() {
        // High-confidence Anthropic detection in the profile must
        // activate the adapter via the default `is_enabled` path
        // (matches `llm/<name>` adapter ID suffix against the
        // `LlmSdkHint::Anthropic` serde spelling `"anthropic"` — locked
        // in by
        // `stryx_index::profile::tests::brand_name_variants_serialize_to_canonical_strings`).
        let profile = ProjectProfile {
            llm_sdks: vec![Detected {
                id: LlmSdkHint::Anthropic,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(AnthropicAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_openai_profile() {
        // An OpenAI-only profile must not activate the Anthropic
        // adapter, even at high confidence — adapter activation is
        // per-name, not per-kind. The OpenAI SDK's call shapes
        // (`<x>.chat.completions.create`, `<x>.responses.create`)
        // belong to `llm/openai`; this adapter must stay dormant so
        // its `anthropic.*` / `client.*` matchers never fire on an
        // OpenAI-only project.
        let profile = ProjectProfile {
            llm_sdks: vec![Detected {
                id: LlmSdkHint::OpenAi,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!AnthropicAdapter.is_enabled(&profile));
    }
}
