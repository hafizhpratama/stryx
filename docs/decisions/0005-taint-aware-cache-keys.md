# ADR 0005 — Taint-aware LLM cache keys

- **Date**: 2026-05-09
- **Status**: Accepted
- **Decider**: Hafizh Pratama
- **Supersedes**: none
- **Refines**: [ADR 0002](0002-hybrid-ast-llm-architecture.md), [ADR 0003](0003-cross-file-and-taint-as-core.md)

## Context

The original LLM cache key from the v0.0 architecture was:

```
blake3(zone_source + rule_id + model_version)
```

This was correct for the v0.0 single-file model where every
UncertainZone was answered by a rule asking a question about *the
zone in isolation*. Two problems surfaced once cross-file taint
analysis became core (ADR 0003):

### Problem 1: same syntactic zone, different taint context

Cross-file taint flows produce UncertainZones whose meaning depends
on the *flow context*, not just the zone source. A function body that
processes `UntrustedInput` from `req.json()` is not equivalent to the
same function body processing a `Secret` from `process.env.X`, even
though the syntactic span is identical.

Caching by zone source alone would return the wrong verdict when the
same function appears in two different flows. The risk is silent
incorrectness — a cached "safe" verdict from one flow context applied
to a fundamentally different question.

### Problem 2: prompt iteration faster than model upgrades

Prompt design is iterative. Tightening a prompt to reduce false
positives is more frequent than bumping the LLM model version. The
v0.0 cache key invalidated only on `model_version` changes — meaning
a prompt fix would silently coexist with cached answers from the old
prompt.

This is a quieter correctness problem (the prompt change presumably
makes verdicts better; cached old answers are merely stale, not
wrong) but it undermines the iterate-on-prompts feedback loop.

## Options considered

### Option A — Keep the simple key

Accept stale verdicts when prompts change; rely on `model_version`
bumps as the invalidation signal.

**Pros:** smaller cache key, fewer cache misses.

**Cons:** silent staleness on prompt iteration; doesn't address the
taint-context problem at all.

Rejected.

### Option B — Add `prompt_hash` only

Bump the key to include a hash of the prompt template. Fixes problem 2
but not problem 1.

**Pros:** small, additive change; fixes the iterate-on-prompts loop.

**Cons:** silent incorrectness on the taint-context problem remains.

Rejected as insufficient.

### Option C (chosen) — Add `taint_summary + prompt_hash`

```
blake3(zone_source + taint_summary + rule_id + prompt_hash + model_version)
```

Where:

- `taint_summary` is a deterministic serialization of the live taint
  state at the zone: source labels, originating source ids, bail
  reason. Two zones with the same source span but different taint
  contexts produce different summaries and cache separately.
- `prompt_hash` is `blake3` of the prompt template content (after
  variable substitution placeholders are normalized but before
  rendering).

**Pros:** correctness on both axes; cache hits remain meaningful;
prompt iteration is safe.

**Cons:** higher cache miss rate (different contexts cache
separately); cache layer must accept `taint_summary` as input.

### Option D — Embedding-based zone similarity lookup

Use semantic embeddings of the zone source as the cache key, with
`rule_id` as a soft filter rather than part of the key.

**Pros:** much higher hit rate across similar (but not identical)
code regions.

**Cons:** non-trivial infrastructure (embedding model, vector store,
similarity threshold tuning); risk of false-positive cache hits when
similar code has different semantics; not v0.1 scope.

Deferred. Reconsider later if cache miss rate proves too costly.

## Decision

The LLM cache key is:

```
blake3(zone_source + taint_summary + rule_id + prompt_hash + model_version)
```

Implementation requirements:

- `stryx_taint` exposes a `TaintSummary::serialize()` that produces a
  stable byte representation suitable for hashing.
- `stryx_llm` produces `prompt_hash` at template-load time and caches
  it per template (templates change at deploy time, not per scan).
- `stryx_cache` accepts the full key tuple and does not hash
  internally — it stores the key bytes directly.
- Both storage layers (in-process and on-disk) use the same key
  format. Cache entries are content-addressed; no schema migration
  needed when components are added — older entries simply stop
  matching the new key shape.

## Consequences

### Positive

- Correctness on the two problems above.
- Prompt iteration becomes a normal-velocity activity — change the
  prompt, deploy, old answers invalidate automatically.
- Different taint contexts get correctly distinct verdicts even when
  syntactic zones overlap.
- The cache key is content-addressed end-to-end; no manual
  invalidation needed when prompts or labels are added.

### Negative

- **Higher cache miss rate.** Same syntactic zone in N different
  taint contexts now requires N separate LLM calls. Worth the
  correctness gain; quantified as ~15–30% miss-rate increase in early
  benchmarks vs the single-key model.
- **Larger key bytes.** Cache storage overhead is negligible (~80
  bytes per entry vs ~50 bytes).
- **Cache layer must understand taint structure.** `stryx_cache`
  takes a typed `CacheKey` rather than a raw byte string; tests must
  assert key shape stability.

### Neutral

- The prompt-template caching strategy at Anthropic (provider-side
  prompt cache) is unaffected — that operates on request bytes, not
  our cache key.
- Determinism mode (`--no-llm`) bypasses the cache entirely; this
  ADR has no effect there.

## Notes

The `taint_summary` serialization must be deterministic across runs.
Implementation guidance for `TaintSummary`:

- Sort label set lexically before serializing
- Sort source ids by their stable string id
- Include the bail reason (one of a finite enum) but not bail-specific
  data that may vary scan-to-scan
- Do not include file paths, scan timestamps, or anything ephemeral

A test in `crates/stryx_taint/tests/cache_key.rs` should assert that
the same zone in the same taint context produces a byte-identical
summary across three independent runs.

The `prompt_hash` should be computed *after* normalizing
substitution placeholders to their stable token names (e.g.,
`{ZONE_SOURCE}` is the normalized form, not the rendered substituted
content). Two prompts that differ only in their substituted content
should hash to the same value; two prompts that differ in their
template body should hash differently.

Reversibility: high. We can fall back to a simpler key by
short-circuiting the `taint_summary` and `prompt_hash` arguments to
empty bytes — at the cost of correctness.

## References

- [ADR 0002](0002-hybrid-ast-llm-architecture.md) — original cache
  key design
- [ADR 0003](0003-cross-file-and-taint-as-core.md) — taint context
  motivation
- [`docs/architecture/llm-escalation.md`](../architecture/llm-escalation.md) —
  cache layers and operational details
- [`docs/architecture/taint-engine.md`](../architecture/taint-engine.md) —
  `TaintSummary` shape
