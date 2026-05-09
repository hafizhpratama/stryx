# ADR 0002 — Hybrid AST + LLM architecture

- **Date**: 2026-05-09
- **Status**: Accepted
- **Decider**: Hafizh Pratama
- **Supersedes**: none
- **Related**: [ADR 0001](0001-rust-and-oxc.md)

## Context

Stryx must catch AI-generated code failure patterns in TypeScript. The
2026 competitive landscape splits into three architectural camps:

1. **Pure AST scanners** (oxlint, Biome, Snyk, Semgrep) — fast,
   deterministic, but blind to semantic intent. Cannot answer questions
   like "does this auth handler actually validate sessions?"
2. **Pure LLM reviewers** (CodeRabbit, Greptile, Cursor BugBot, Qodo) —
   smart, context-aware, but slow (10–30s/PR), expensive (~$0.50/PR),
   and non-deterministic. Run only at PR-time.
3. **Static rule packs** (eslint-plugin-security, etc.) — pattern-based,
   limited to what someone wrote a rule for, slow on large codebases.

None of these camps clearly serve "indie developer to mid-size team
shipping AI-generated TypeScript." Each has blind spots that matter for
this audience.

## Options considered

### Option A — Pure AST analysis

Build only Layer 2 deterministic rules. No LLM.

**Pros:**
- Simple architecture
- Fully deterministic, free to run, no API keys required
- Fast (sub-second scans)
- Easy to reason about and test

**Cons:**
- Cannot catch semantic patterns ("intent without form")
- Misses the 20% of issues where context matters
- Competes head-on with oxlint/Biome on similar surface area
- Not differentiated from existing tools

### Option B — Pure LLM analysis

Send entire files (or whole codebases) to an LLM for analysis.

**Pros:**
- Maximum context awareness
- No rule-writing required
- Can catch novel patterns

**Cons:**
- Expensive at scale (~$0.50–$1/PR like CodeRabbit)
- Slow (5–30s per file)
- Non-deterministic (same input, slightly different outputs)
- Privacy concerns (sending full source to third-party)
- Already crowded competitive space

### Option C — Hybrid: AST + LLM escalation (chosen)

Layer 2 (AST) catches the 80% of issues that are syntactically detectable.
Layer 3 (LLM) is invoked only on AST-flagged ambiguous zones, with results
cached aggressively.

**Pros:**
- Catches deterministic issues fast and free
- Catches semantic issues with LLM context, but only where needed
- Cost stays low (~$0.001/scan after first scan due to caching)
- Determinism is opt-in (`--no-llm` for reproducible CI)
- Architecturally distinct from any single-layer competitor
- Privacy-preserving (only flagged zones leave the machine)

**Cons:**
- More complex to implement than either pure approach
- Requires careful prompt engineering per rule
- Cache management adds engineering surface
- Can be seen as "two products in one" — must communicate clearly

## Decision

**Use the hybrid AST + LLM escalation architecture.**

Specifically:
- Layer 1: oxc-based parsing
- Layer 2: deterministic Rust rules emitting either Findings (definite)
  or UncertainZones (maybe)
- Layer 3: LLM analysis triggered by UncertainZones, with content-hashed
  caching, optional per scan via `--no-llm`

The hybrid is what lets the engine be both fast (most issues caught
deterministically in milliseconds) and contextual (the genuinely
ambiguous zones get LLM intent confirmation, cached so repeat scans
are free).

## Consequences

### Positive

- **Coverage**: AST handles the bulk of patterns deterministically;
  LLM handles the small remainder where intent matters. Each layer
  does what it's good at.
- **Cost economics**: aggressive content-hash caching means LLM cost
  is bounded; repeat scans on unchanged code are free.
- **Speed**: AST-only mode runs in seconds even on big repos, suitable
  for pre-commit hooks. LLM mode adds 10–60s for cold zones, near-zero
  for cached.
- **Privacy story**: zones-only LLM submission keeps source disclosure
  to a small fraction of the file, which matters for projects that
  cannot send full source to a third-party model.
- **Future flexibility**: Layer 3 can be swapped (Anthropic → OpenAI →
  local Ollama → in-house specialized model) without touching Layer 2.

### Negative

- **Engineering complexity**: caching, prompt management, fallback
  handling are real surface area. Need careful testing.
- **Marketing complexity**: explaining "AST + LLM hybrid" is harder
  than "AI scanner" or "static analyzer." We rely on the comparison
  table in README to make the distinction clear.
- **Failure mode handling**: when LLM is unavailable, we degrade to
  AST-only with inconclusive findings. Documented but real.

### Neutral

- The Layer 2/3 boundary is enforceable in tests. A rule that emits an
  UncertainZone but no prompt template is caught at CI time.
- Layer 2 rules can ship without Layer 3 prompts. Layer 3 is opt-in
  per rule.

## Implementation order

Layer 2 is the first to ship; Layer 3 follows once we have observed
which rules genuinely produce ambiguous zones in real usage. This
sequencing means:

- Early users get value immediately from deterministic rules
- We learn which rules need LLM escalation by observing UncertainZones
  in real usage before building the LLM layer
- The LLM layer is opt-in from day one (`--no-llm` for AST-only
  scans; bring your own API key when Layer 3 is enabled)

## What this rules out

- **Multi-pass LLM analysis.** No "LLM checks the LLM's findings." Adds
  cost and non-determinism without commensurate accuracy gains.
- **LLM-only rules.** Every rule must have an AST component, even if
  weak (e.g., "find the function" is AST; "is it correct" is LLM).
  Pure LLM rules creep toward CodeRabbit territory.
- **Generic LLM "find security issues" prompts.** Always tied to a
  specific rule_id. Generic prompts produce noise.

## Open questions

- How do we version a rule when its LLM prompt is improved? Resolved
  in [ADR 0005](0005-taint-aware-cache-keys.md): the cache key
  includes a `prompt_hash` so prompt iteration invalidates stale
  answers automatically.
- For air-gapped users who can't make outbound network calls, the
  current answer is `--no-llm` (deterministic local-only scans) plus
  the `OllamaClient` for fully local Layer 3 against a self-hosted
  model. A bundled local model is a possible future addition.

## References

- See [docs/architecture/llm-escalation.md](../architecture/llm-escalation.md)
  for the implementation details of Layer 3.
- See [ARCHITECTURE.md](../../ARCHITECTURE.md) for the full pipeline.
