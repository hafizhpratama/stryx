# ADR 0001 — Use Rust with oxc as the engine foundation

- **Date**: 2026-05-09
- **Status**: Accepted
- **Decider**: Hafizh Pratama
- **Supersedes**: none

## Context

We need to choose a language and parser for the Stryx engine. The product
is a TypeScript static analyzer targeting solo developers up to enterprise
teams. Performance, distribution, and long-term maintainability matter.

The 2026 landscape:

- **JavaScript/TypeScript engines**: ESLint (slow, JS-based), tsc parser
  (TS-based, slow), Babel (JS-based, slow). All have rich ecosystems but
  poor performance at scale.
- **Rust engines**: oxc (oxc-project, MIT, MIT, fastest), swc (Apache 2.0,
  battle-tested via Next.js/Turbopack), Biome's parser (MIT/Apache, in
  active development).
- **Go engines**: esbuild's parser is excellent but the ecosystem around
  custom analysis tooling is small.

The trend in 2026 dev tooling is unmistakably Rust — oxlint, Biome, swc,
Ruff (Python), Rolldown all prove the model.

## Options considered

### Option A — TypeScript with `ts-morph` or oxc-parser via napi

**Pros:**
- Fastest time to MVP (~6 weeks)
- The user (solo founder) can dogfood the product on its own codebase
- Massive ecosystem of TS dev tools to integrate with

**Cons:**
- Slow at scale — even with Rust-based parsing via napi, the rules layer
  in TS is the bottleneck on big monorepos
- Heavy npm install footprint
- Distribution is npm-only (no single binary, no brew, no cargo)
- Long-term ceiling — would need full rewrite to Rust eventually

### Option B — Rust with swc

**Pros:**
- Proven at scale (Next.js, Turbopack use it)
- Rich ecosystem (transformer, minifier, parser all available)
- Apache 2.0 license

**Cons:**
- swc's API is more complex than oxc's
- Less ergonomic for static-analysis-style traversal
- Optimized for compilation/transformation, not analysis

### Option C — Rust with oxc (chosen)

**Pros:**
- Fastest TS parser in the ecosystem (50–100x faster than ESLint per
  oxc benchmarks)
- MIT license — maximum freedom
- Designed for analysis tooling (oxlint is built on it, similar shape
  to what we're building)
- Backed by VoidZero (Vite team) — strong long-term support
- Arena-allocated AST keeps memory predictable
- Integrates well with `oxc_semantic` for scope/symbol resolution

**Cons:**
- Newer than swc (less battle-tested in production at scale)
- Smaller ecosystem of related tools
- Active API evolution (we'll need to track upstream changes)

### Option D — Rust with Biome's parser

**Pros:**
- MIT/Apache dual license
- Designed for IDE integration (recoverable parsing)
- Active development

**Cons:**
- Tighter coupling to Biome's overall design
- Less of a clean library; more of an internal component

## Decision

**Use Rust as the engine language. Use oxc as the parser via cargo
dependencies (not fork).**

Specifically:
- `oxc_parser` for parsing
- `oxc_ast` for node types (wrapped in our own `stryx_ast` for swappability)
- `oxc_semantic` for scope and symbol resolution
- `oxc_allocator` for arena allocation

We do NOT fork oxc. We depend on it as a versioned crate. We ride
upstream improvements, contribute back generic fixes, and pin versions
with planned upgrade windows quarterly.

## Consequences

### Positive

- Single-binary distribution (Mac, Linux, Windows) via the standard
  Rust release pipeline
- npm distribution via `napi-rs` — `npm install stryx` Just Works
- Performance ceiling is high enough we won't need to rewrite for years
- Hiring: when we're ready to hire, "Rust engineer who knows ASTs"
  is a recruitable archetype
- Upgrade story: oxc's pre-1.0 minor cadence (currently 0.129.x) is
  visible and predictable; we pin a single minor at the workspace
  level and bump deliberately

### Negative

- Higher upfront cost vs TS path (~12 weeks to MVP vs ~6)
- Learning curve for future contributors (mitigated by the user's 3
  years of Rust experience)
- We track oxc's API evolution actively (pin and review quarterly)
- Limited ability to hot-patch rules — they require recompile

### Neutral

- The contract test (no oxc imports in `stryx_rules`) protects against
  parser lock-in. If oxc disappeared tomorrow, swapping to swc is a
  measured project, not a rewrite.

## Notes

The user has 3 years of Rust experience, which inverts the standard
solo-founder advice ("start in TS, port to Rust later"). For a Rust-
fluent founder, starting in Rust avoids two transitions and costs only
the upfront learning of oxc specifically.

The decision is reversible at the parser layer (swap to swc/biome via
adapter rewrite) but not at the language layer (swap to TS = full
rewrite). The contract test enforces the parser-swap optionality.

## References

- [oxc benchmarks](https://github.com/oxc-project/bench-javascript-linter)
- [oxc on crates.io](https://crates.io/crates/oxc_parser)
- The broader trend of Rust-authored JS/TS tooling (oxlint, Biome,
  swc, Rolldown, Ruff) is well-documented across 2024–2026 dev-tooling
  retrospectives; primary sources should be cited inline if specific
  claims rely on them.
