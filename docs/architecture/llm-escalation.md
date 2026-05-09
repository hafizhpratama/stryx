# LLM Escalation (Layer 3)

When and how Stryx escalates from deterministic AST analysis to a Large
Language Model for context-aware analysis.

## When it fires

A Layer 3 escalation happens when:

1. A Layer 2 (AST) Rule emits an `UncertainZone` instead of (or in
   addition to) a Finding
2. LLM escalation is enabled in config (`[llm].enabled = true`, default true)
3. The user has not passed `--no-llm` on the CLI
4. The (zone, rule, model) tuple is not already in the cache

If any of these conditions fail, the UncertainZone is either reported as
"inconclusive" (CLI shows it but doesn't fail CI) or dropped silently
(in deterministic-only mode).

## Why escalation exists

Some checks are inherently ambiguous from AST alone:

```ts
// Does this validate?
const result = await validateAndStoreUser(req.body);
```

`validateAndStoreUser` could be a thin wrapper that does validate, or
a function that doesn't. Static analysis cannot know without inlining the
called function (which gets expensive across files and breaks at module
boundaries).

LLM escalation lets us answer these "intent" questions without writing
fragile heuristics.

## What escalation is NOT

- **Not a replacement for AST rules.** AST rules catch 80% of issues
  faster, cheaper, and deterministically. LLM is the 20% fallback.
- **Not a code reviewer.** It does not generate suggestions or rewrite
  code. It only answers structured yes/no questions defined per Rule.
- **Not used for new patterns.** Each Rule's escalation prompt is
  hand-crafted in `crates/stryx_llm/prompts/`. We don't ask the LLM
  to "find vulnerabilities" — that's expensive and noisy.

## The escalation flow

```
1. Rule emits UncertainZone with:
   - rule_id          (which rule wants the answer)
   - zone             (file path + byte range)
   - reason           (one sentence: why uncertain)
   - extracted_source (the actual code text of the zone)

2. stryx_core batches UncertainZones across all files

3. For each zone:
   cache_key = blake3(extracted_source + taint_summary + rule_id + prompt_hash + model_version)
   if cached: use cached verdict, skip LLM
   else: queue for LLM call

4. LLM client batches queued zones (max 5 per call to keep latency low)

5. For each zone, the prompt template for that rule_id is loaded from
   crates/stryx_llm/prompts/{rule_id}.txt and {ZONE_SOURCE} is substituted

6. LLM returns structured JSON per zone (we use response_format=json)

7. Result is cached and returned

8. If verdict.confidence >= rule's threshold: convert to Finding
   else: drop or report as info-level
```

## Prompt templates

Each rule that escalates has a prompt file at:

```
crates/stryx_llm/prompts/<category>/<rule-id>.txt
```

For example: `crates/stryx_llm/prompts/flow/unvalidated-body-to-db.txt`.
The `<category>` matches the rule's source folder
(`flows`/`sources`/`sinks`/`sanitizers`).

A prompt template:

```
You are analyzing a Next.js API route handler for input validation.

Source code:
{ZONE_SOURCE}

Question: Does this handler validate the request body at runtime before
using it for any database write, file operation, or business logic?

Definitions:
- "Validation" means a runtime check of the body's shape and types using
  zod, valibot, ajv, yup, joi, or a custom validator with similar semantics.
- TypeScript type assertions (`as User`) are NOT validation.

Return JSON only, no prose:
{
  "validated": boolean,
  "validator": string | null,
  "confidence": number,
  "reasoning": string
}
```

Prompt design principles:
- **Be specific.** Define what counts and what doesn't.
- **Ask one question.** Multi-part questions confuse models and dilute
  confidence scores.
- **Demand structured output.** JSON only, schema documented inline.
- **No "find all the bugs" prompts.** Always tied to a specific Rule.

## The `LlmClient` trait

Pluggable provider interface in `crates/stryx_llm/src/lib.rs`:

```rust
#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn analyze(
        &self,
        prompt: &str,
        zone: &UncertainZone,
    ) -> Result<EscalationVerdict, LlmError>;

    fn model_id(&self) -> &str;
    fn cost_estimate(&self, prompt: &str) -> f64;  // USD
}
```

Built-in implementations:
- `AnthropicClient` — default, uses Claude Haiku 4.5 (cheap, fast)
- `OpenAiClient` — for users who prefer OpenAI
- `OllamaClient` — local LLM via Ollama (offline, free)

Additional providers (Azure OpenAI, AWS Bedrock, etc.) can be added
behind the same `LlmClient` trait without touching rule code.

## Caching

Escalations are cached at two levels:

### In-process (per-scan)

`dashmap::DashMap<CacheKey, EscalationVerdict>` lives for the
duration of one scan invocation. Catches the case where the same
zone source appears in multiple files within a single scan.

### On-disk (per-user)

Default location: `~/.cache/stryx/llm/`. SQLite-backed. Persists
across scans, expires entries after 30 days of disuse.

The on-disk cache is the biggest cost saver. A user running scans
daily on the same repo gets near-100% cache hit rate after the first
scan.

The cache key includes `model_version` *and* `prompt_hash`, so a
prompt improvement automatically invalidates old answers — even when
the model itself is unchanged. The key also includes a `taint_summary`
so the same syntactic zone in a different flow context caches
separately. See [ADR 0005](../decisions/0005-taint-aware-cache-keys.md).

## Cost optimization

Three controls keep LLM cost low:

### 1. Aggressive caching (described above)

Average scan after the first is ~$0.001 because most zones are cached.

### 2. Default to cheap models

We default to Claude Haiku 4.5: ~$0.80/M input tokens, ~$4/M output.
Each escalation is ~500 input tokens, ~150 output tokens. Cost per
zone: ~$0.001.

Users can override to a more expensive model if they want higher
accuracy:

```toml
[llm]
model = "claude-opus-4-7"  # ~30x cost, marginal accuracy gain
```

### 3. Confidence threshold filtering

LLM verdicts with `confidence < 0.7` are demoted out of the main
findings list and surfaced separately at info severity, with the
verdict text included for transparency. This keeps the headline
output high-precision while still showing what the LLM saw.

## Determinism mode

For reproducible CI, `--no-llm` disables Layer 3 entirely. The same
commit always produces the same output.

In this mode, UncertainZones are reported as "inconclusive" findings
at info-level (not failing CI). They serve as hints for human review
but do not gate deployment.

`--no-llm` is the right choice for environments that need byte-stable
output across runs (some compliance / audit pipelines), or for
contributors who don't want any external LLM calls during development.

## Privacy and data handling

Stryx is a CLI you run locally. Code never leaves your machine
unless you explicitly enable Layer 3, and even then only the flagged
zone source — not whole files, file paths, repo names, or user
identifiers — is sent to the LLM client you configured.

### Bring-your-own API key

Stryx talks directly to the LLM provider you point it at (Anthropic,
OpenAI, etc.). The provider's data-handling terms govern what
happens to the zone content. Whatever zero-data-retention or
training-opt-out terms you have with that provider apply unchanged.
Review your provider's data agreement before enabling Layer 3 on
sensitive code.

### Local model via `OllamaClient`

- All processing is local.
- No network calls beyond the local Ollama process.
- Suitable for air-gapped environments.

### `--no-llm`

Disables Layer 3 entirely. AST and taint analysis run normally; no
network calls happen at any point. UncertainZones are reported as
inconclusive info-level findings.

## Failure modes

What happens when LLM is unavailable mid-scan:

- **Network failure**: retry with exponential backoff (max 3 attempts).
  If still failing, emit "inconclusive" findings for the affected zones.
  AST findings are unaffected.
- **Rate limit**: respect `Retry-After` header, queue and retry. If
  budget is exhausted, fall back to inconclusive.
- **Malformed LLM response**: log, treat as inconclusive. Track these
  in metrics — high rates indicate prompt engineering issues.
- **Cache corruption**: detect via hash mismatch, clear, recompute.
  Never crash on cache.

In all failure modes, AST findings are reported normally. The scan never
fails because of LLM issues.

## Adding a new LLM-escalating rule

1. In your Rule's `visit()` method, emit `UncertainZone` for ambiguous
   cases (in addition to or instead of `Finding`)
2. Create the prompt template at
   `crates/stryx_llm/prompts/<category>/<rule-id>.txt`
3. The orchestrator will automatically route UncertainZones to the
   prompt — no extra wiring needed
4. Document the prompt in your rule doc under "LLM escalation prompt"
5. Add an integration test that asserts the right verdict on a real
   zone (mocking the LLM client for determinism)

## Roadmap

- **Q3 2026**: BYO model support (custom endpoints, custom prompts)
- **Q4 2026**: Multi-model voting for high-stakes findings
- **2027**: Smaller specialized models for specific rule classes
  (e.g., a small auth-validation classifier)
