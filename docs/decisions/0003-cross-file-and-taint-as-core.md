# ADR 0003 — Cross-file taint analysis as v0.1 core

- **Date**: 2026-05-09
- **Status**: Accepted
- **Decider**: Hafizh Pratama
- **Supersedes**: none
- **Refines**: [ADR 0001](0001-rust-and-oxc.md), [ADR 0002](0002-hybrid-ast-llm-architecture.md)

## Context

Earlier planning had v0.1 ship with per-file syntactic and scope
analysis, deferring cross-file analysis to a later phase.

A doc audit (May 2026) surfaced two problems with that plan:

1. **Many of the patterns we want to catch are inherently cross-file.**
   Of the eight failure patterns initially scoped for v0.1, five
   require cross-file analysis or type information that a per-file
   model cannot provide:
   - Missing rate limits — middleware in another module
   - Server Actions without auth — auth wrapper imported from a helper
   - Direct DB access in RSC — RSC boundary detection via imports
   - CORS over-permission — cross-file middleware setup
   - Type-as-validation fallacy — needs type information

2. **A later v0.x pivot from per-file to cross-file is a rewrite, not
   an extension.** The arena-per-file lifetime model, the `Rule`
   trait shape, and the rule library organization would all need to
   change. Pushing the pivot to v0.3+ means investing in code we
   would later discard.

The architectural question: design v0.1 around cross-file flow
analysis from the start, or stay per-file and accept the cross-file
pivot later?

## Options considered

### Option A — Per-file v0.1, expand to cross-file in v0.3+

**Pros:**
- Less foundational infrastructure for the first release.
- Aligns with "boring stack, scale later" instincts.

**Cons:**
- Roughly half of the v0.1 rule list cannot ship under this model;
  the user-visible surface is much thinner than planned.
- The eventual cross-file pivot is a memory-model and trait-shape
  rewrite, not an additive change.

Rejected.

### Option B — Cross-file v0.1, but defer LLM escalation to v0.2

**Pros:**
- Foundational cross-file infrastructure is in place from the start.
- LLM is incremental; deferring is less risky.

**Cons:**
- Cross-file taint without LLM hits a precision ceiling on dynamic
  TypeScript: dynamic dispatch, computed access, framework reflection.
- Without an LLM as a recovery path, the engine must choose between
  high false-positive rates (sound) and silent misses (precise);
  neither is acceptable for a security tool.

Rejected.

### Option C (chosen) — Cross-file taint + LLM escalation as v0.1 core

**Pros:**
- Inter-procedural taint analysis is the right primitive for the
  patterns we want to catch.
- The rule library composes around source / sink / sanitizer
  abstractions; adding a new framework becomes new source/sink
  adaptations rather than rewriting rules.
- LLM escalation has a clear architectural role (precision recovery
  on bail-out), not a vague "smart bonus."
- Function-summary caching means repeat scans on unchanged code are
  near-free at the taint layer.

**Cons:**
- Roughly three months of foundational infrastructure
  (`stryx_index`, `stryx_taint`) before the first user-visible rule
  lands.
- The per-file arena lifetime model is replaced; memory model and
  performance budgets are recast at the project scope.
- Rule contributors need to understand source / sink / sanitizer
  concepts, not just AST visitors.
- Soundness vs precision becomes a first-class design tension.

## Decision

Cross-file taint analysis with LLM escalation is v0.1 core.

Concretely:

- New crate `stryx_index`: project-level semantic index built from all
  parsed ASTs (symbol table, import graph, intra-file call graph).
- New crate `stryx_taint`: inter-procedural taint engine with
  source / sink / sanitizer abstractions and content-keyed function
  summaries.
- Per-file arena lifetime model is replaced. Files are parsed in
  parallel into per-file arenas; index entries are extracted; arenas
  are freed; cross-file rules query the index and trigger on-demand
  re-parsing for the few zones that need full AST inspection.
- The `Rule` trait gains `interests()`, `taint_signature()`, and
  `scope()` (`SingleFile` or `CrossFile`) so the orchestrator can
  dispatch efficiently and contributors are explicit about scope.
- The rule library is reorganized around source / sink / sanitizer
  under `crates/stryx_rules/src/{sources,sinks,sanitizers,flows}/`.
- v0.1 ships three flow rules that demonstrate the technique:
  - `flow/unvalidated-body-to-db`
  - `flow/auth-bypass-via-wrapper`
  - `flow/secret-to-response`
- LLM escalation is the precision-pressure-relief valve. When the
  taint engine bails (dynamic dispatch, computed access, eval-shape,
  recursion limit), it emits an `UncertainZone` for Layer 3.
- Soundness/precision stance: **precision over soundness.** A
  noisy security tool gets muted; a precise security tool that
  occasionally misses real issues remains useful as one defense among
  several. Documented in `docs/architecture/taint-engine.md`.
- TypeScript-only through the foreseeable roadmap. Depth (more
  frameworks, more source/sink coverage, type-aware analysis) beats
  breadth (additional languages).

## Consequences

### Positive

- The architecture matches the patterns we actually want to catch.
- The rule library composes; adding a new framework is mostly
  source/sink adaptation, not rule rewriting.
- Memory model improves: index entries are ~100 bytes per function
  vs whole arenas resident.
- Function-summary caching means repeat scans on unchanged code are
  near-free at the taint layer, not just at the LLM layer.
- LLM escalation has a coherent architectural role.

### Negative

- v0.1 ships later by roughly three months for foundational
  infrastructure.
- Several docs become incorrect and need rewrites:
  `ARCHITECTURE.md` ("what we don't build"), `ast-pipeline.md`
  (memory model), `CLAUDE.md` (rule paths and roadmap), `README.md`
  (positioning sharpened around cross-file).
- The earlier "≤500MB memory cap" claim is replaced with a
  project-scope budget that needs measurement on real fixtures.
- The performance budget is recast at per-relevant-node and
  per-project rather than per-file; `rule-format.md` and budget
  tables in `CLAUDE.md` and `ARCHITECTURE.md` change.
- Soundness is sacrificed by design — we will miss some real
  issues; this needs to be explicit in user-facing docs so
  expectations are calibrated.

### Neutral

- The `stryx_ast` parser-swap contract test still holds: rules query
  the normalized AST and the project index, never `oxc_*` directly.
- Async-only-at-LLM-boundary still holds; the index and taint engine
  are CPU-bound and run on the rayon pool.
- napi-rs distribution unchanged; cross-file analysis is engine-internal.
- The "no rule DSL until 30+ rules" constraint still holds — the
  taint engine is a shared library, not a rule DSL.

## Notes

The biggest implementation risk is performance on large monorepos.
Function-summary caching is the load-bearing optimization; without
it, inter-procedural analysis on a 100k-file repo is intractable.
Build the cache layer in the first sprint, even before the engine is
feature-complete.

The LLM-as-precision-recovery framing is what makes the design
architecturally coherent. It also constrains prompt design: prompts
ask "does taint label X reach sink Y unsanitized in this region?"
rather than open-ended "is this code safe?" Open-ended security
prompts are noisy and expensive; constrained taint-recovery prompts
are tractable.

Reversibility is low. Once `stryx_index` and `stryx_taint` are
load-bearing for shipped rules, rolling back to per-file v0.1 means
deleting most of the rule library. Treat this ADR as a foundational
commitment.

## References

- [ADR 0001](0001-rust-and-oxc.md) — Rust + oxc foundation
- [ADR 0002](0002-hybrid-ast-llm-architecture.md) — hybrid AST + LLM rationale
- [ADR 0005](0005-taint-aware-cache-keys.md) — taint-aware LLM cache keys
- [`docs/architecture/taint-engine.md`](../architecture/taint-engine.md) — engine design
- [`docs/architecture/semantic-index.md`](../architecture/semantic-index.md) — index design
- [`docs/architecture/cross-file-rules.md`](../architecture/cross-file-rules.md) — when to use the index, taint, or LLM
- [Semgrep Pro taint mode](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/) — reference for precision-first taint
- [CodeQL data-flow analysis](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/) — reference for sound inter-procedural analysis
