//! `llm/openai` adapter — OpenAI SDK prompt-creation surfaces.
//!
//! OpenAI is the most widely deployed LLM SDK in TypeScript backends.
//! Its prompt-creation calls drive `flow/prompt-injection`. This adapter
//! mirrors the call shapes the inline recogniser in
//! [`crate::steps::sinks::llm::is_llm_prompt_sink_call`] already
//! matches (`<x>.chat.completions.create`, `<x>.responses.create`),
//! re-expressed as substrate patterns so rule migration is byte-
//! equivalent.
//!
//! ## Sinks
//!
//! All three OpenAI prompt entry points carry `SinkKind::LlmPrompt`
//! with `Severity::High` — prompt injection is OWASP LLM01 and the
//! consequences (instruction override, data exfiltration, tool abuse)
//! are uniformly high-impact for any LLM-backed product. The severity
//! floor matches the `severity_hint` returned by the existing
//! `LlmPromptSink` step.
//!
//! Three pattern IDs are exposed, one per OpenAI API surface:
//!
//! - `llm/openai/chat-completions-create` —
//!   `<x>.chat.completions.create({ messages: [...] })`, the canonical
//!   Chat Completions API. The dominant OpenAI shape in production
//!   TypeScript backends.
//! - `llm/openai/responses-create` — `<x>.responses.create({ input })`,
//!   OpenAI's newer Responses API (replaces the assistants/threads
//!   surface for most use cases). Recognised by the inline step's
//!   `responses` arm.
//! - `llm/openai/completions-create` — legacy `<x>.completions.create`,
//!   the pre-chat text-completion endpoint. Still widely used by
//!   instruction-tuned `gpt-3.5-turbo-instruct` callers.
//!
//! ## Receiver-name limitation
//!
//! The substrate's [`AstMatcher::MethodCall`] requires a literal dotted
//! receiver chain — there is no "method-chain whose tail matches X"
//! matcher in the current variant set. The inline recogniser accepts
//! *any* receiver expression because the path shape itself
//! (`.chat.completions.create`) is provider-specific enough that false
//! positives are vanishingly rare.
//!
//! Bridging that gap without adding a new `AstMatcher` variant: each
//! API surface registers two receiver variants in a single pattern —
//! `openai.*` (the SDK's documented binding name) and `client.*` (the
//! near-universal alternative, e.g. `const client = new OpenAI()`).
//! Both matchers live under one `SinkPattern` so a finding is
//! attributed to the *API surface* (Chat Completions vs Responses vs
//! legacy Completions), not to which binding name happened to match.
//! Other binding names (`ai`, `gpt`, branded names) are intentionally
//! out of scope at the adapter layer; the inline recogniser still
//! covers them until rules consume `ctx.match_sink` and the
//! substrate gains a trailing-chain matcher.
//!
//! ## Activation
//!
//! Default `is_enabled` — active when the project profile contains an
//! `LlmSdkHint::OpenAi` entry at confidence ≥
//! [`crate::adapters::ENABLE_CONFIDENCE_FLOOR`] (`0.60`). The profile
//! crate serialises `OpenAi` as `"openai"` (per the brand-name
//! lock-in in [`stryx_index::profile`]), which matches the `openai`
//! suffix in this adapter's `llm/openai` ID. A project on Anthropic
//! (`LlmSdkHint::Anthropic`) must not activate this adapter even at
//! high confidence — adapter activation is per-name, not per-kind.

use crate::adapters::{AdapterId, AdapterKind, AstMatcher, SinkKind, SinkPattern, StackAdapter};
use stryx_core::Severity;

pub struct OpenAiAdapter;

// =============================================================================
// Sink patterns — OpenAI prompt-creation surfaces
// =============================================================================
//
// One `SinkPattern` per API surface. Each pattern lists the two
// receiver-name variants (`openai.*`, `client.*`) it should fire on;
// the substrate evaluates matchers as a union so either receiver match
// activates the pattern.

static SINKS: &[SinkPattern] = &[
    // Chat Completions API — the dominant OpenAI shape.
    // `<x>.chat.completions.create({ messages: [...] })`.
    SinkPattern {
        id: "llm/openai/chat-completions-create",
        sink: SinkKind::LlmPrompt,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "openai.chat.completions",
                method: "create",
            },
            AstMatcher::MethodCall {
                receiver: "client.chat.completions",
                method: "create",
            },
        ],
        severity_floor: Severity::High,
    },
    // Responses API — OpenAI's newer surface.
    // `<x>.responses.create({ input })`.
    SinkPattern {
        id: "llm/openai/responses-create",
        sink: SinkKind::LlmPrompt,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "openai.responses",
                method: "create",
            },
            AstMatcher::MethodCall {
                receiver: "client.responses",
                method: "create",
            },
        ],
        severity_floor: Severity::High,
    },
    // Legacy Completions API — pre-chat text completion.
    // `<x>.completions.create({ prompt })`.
    SinkPattern {
        id: "llm/openai/completions-create",
        sink: SinkKind::LlmPrompt,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "openai.completions",
                method: "create",
            },
            AstMatcher::MethodCall {
                receiver: "client.completions",
                method: "create",
            },
        ],
        severity_floor: Severity::High,
    },
];

impl StackAdapter for OpenAiAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("llm/openai")
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
    fn openai_adapter_exposes_expected_sink_patterns() {
        let sinks = OpenAiAdapter.sinks();
        assert_eq!(sinks.len(), 3);
        let ids: Vec<&str> = sinks.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"llm/openai/chat-completions-create"));
        assert!(ids.contains(&"llm/openai/responses-create"));
        assert!(ids.contains(&"llm/openai/completions-create"));

        // Every OpenAI sink pattern carries the `LlmPrompt` semantic
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
    fn openai_adapter_is_llm_sdk_kind() {
        assert_eq!(OpenAiAdapter.kind(), AdapterKind::LlmSdk);
        assert_eq!(OpenAiAdapter.id(), AdapterId("llm/openai"));
    }

    #[test]
    fn openai_sinks_floor_at_high() {
        // Prompt injection is OWASP LLM01 — the floor matches the
        // `Severity::High` hint returned by the existing
        // `LlmPromptSink` step (see
        // `crate::steps::sinks::llm::LlmPromptSink::as_sink`). The
        // rule is free to raise but not lower this for specific
        // findings.
        for sink in OpenAiAdapter.sinks() {
            assert_eq!(
                sink.severity_floor,
                Severity::High,
                "LLM-prompt sink {} should floor at High",
                sink.id
            );
        }
    }

    #[test]
    fn is_enabled_returns_true_under_openai_profile() {
        // High-confidence OpenAI detection in the profile must activate
        // the adapter via the default `is_enabled` path (matches
        // `llm/<name>` adapter ID suffix against the
        // `LlmSdkHint::OpenAi` serde spelling `"openai"` — locked in
        // by `stryx_index::profile::tests::brand_name_variants_serialize_to_canonical_strings`).
        let profile = ProjectProfile {
            llm_sdks: vec![Detected {
                id: LlmSdkHint::OpenAi,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(OpenAiAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_anthropic_profile() {
        // An Anthropic-only profile must not activate the OpenAI
        // adapter, even at high confidence — adapter activation is
        // per-name, not per-kind. The Anthropic SDK's call shapes
        // (`<x>.messages.create`) belong to a separate adapter; this
        // adapter must stay dormant so its `openai.*` / `client.*`
        // matchers never fire on an Anthropic-only project.
        let profile = ProjectProfile {
            llm_sdks: vec![Detected {
                id: LlmSdkHint::Anthropic,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!OpenAiAdapter.is_enabled(&profile));
    }
}
