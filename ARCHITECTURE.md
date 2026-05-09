# Stryx Architecture

> Deep design reference. Read this before making structural changes.
> Last reviewed: 2026-05-09

## Design goals

In priority order:

1. **Catch real AI failure patterns** in TypeScript with high precision
2. **Be fast** — sub-30s scans on a 10k-file Next.js monorepo without LLM
3. **Be cheap** — < $0.01 average cost per scan with LLM escalation
4. **Be deterministic** — same code + same rules → same findings, always
5. **Be replaceable** — every component swappable without rewriting others
6. **Stay solo-buildable** — boring stack, monolith first, scale later

When goals conflict, the higher-priority one wins. Specifically: precision
beats recall (false positives kill trust), determinism beats clever
heuristics, simple beats elegant.

## The 3-layer pipeline

```
┌──────────────────────────────────────────────────────────┐
│  LAYER 3: LLM Semantic Analysis                          │
│  - Triggered by: UncertainZone emitted from Layer 2      │
│  - Cached by: blake3(zone_source + rule_id + model)      │
│  - Optional: --no-llm flag disables for deterministic CI │
│  - Cost: ~$0.001/zone with caching                       │
├──────────────────────────────────────────────────────────┤
│  LAYER 2: Rust AST Pattern Detection                     │
│  - Deterministic visitor-based rules                     │
│  - Emits Findings (definite) and UncertainZones (maybe)  │
│  - Performance budget: ≤ 10ms/file p99                   │
│  - Runs on every file in parallel via rayon              │
├──────────────────────────────────────────────────────────┤
│  LAYER 1: Rust Parser (oxc)                              │
│  - oxc_parser → arena-allocated AST                      │
│  - oxc_semantic → scope/symbol resolution                │
│  - Wrapped in stryx_ast for swappability                 │
└──────────────────────────────────────────────────────────┘
```

### Why hybrid AST + LLM

A pure-AST analyzer catches syntactic patterns reliably but misses
semantic intent — for example, whether a custom helper function
sitting between a source and a sink actually validates the data, or
whether a wrapper function named `withAuth` actually verifies a
session. A pure-LLM analyzer can reason about intent, but at the cost
of latency, per-call expense, and non-determinism.

Stryx combines both:

- The vast majority of issues are syntactic-enough that AST and
  index-driven rules catch them in milliseconds. Deterministic, fast,
  free to run.
- The remainder are genuinely contextual ("does this helper actually
  validate the body?", "does this wrapper actually verify the
  session?"). Layer 3 inspects only those zones, with verdicts cached
  by content hash so repeat scans are free.

[ADR 0002](docs/decisions/0002-hybrid-ast-llm-architecture.md) records
the full reasoning.

## Crate workspace

The canonical workspace layout lives in [CLAUDE.md](CLAUDE.md#workspace-layout).
Summary of crate responsibilities below.

```
stryx/
├── crates/
│   ├── stryx_core/        # Scan orchestration, pipeline, public API
│   ├── stryx_ast/         # Normalized AST + visitor traits
│   ├── stryx_index/       # Project semantic index (ADR 0003)
│   ├── stryx_taint/       # Inter-procedural taint engine (ADR 0003)
│   ├── stryx_rules/       # Source/sink/sanitizer/flow rules
│   ├── stryx_llm/         # Layer 3 escalation client + prompts
│   ├── stryx_reporter/    # JSON, SARIF, text, GitHub annotations
│   ├── stryx_cache/       # Content-hash cache abstraction
│   ├── stryx_cli/         # Binary (clap-based)
│   └── stryx_napi/        # napi-rs bindings for npm distribution
├── plugins/               # Future: WASM rule plugins
├── benches/               # Criterion benchmarks
├── xtask/                 # Custom build tasks
└── docs/                  # rules/, architecture/, decisions/
```

### Crate responsibilities (one job each)

- **`stryx_core`** owns: pipeline orchestration, the `Scanner` struct, the
  public `Finding` and `Verdict` types. Everything else is internal detail.

- **`stryx_ast`** owns: the normalized AST (`StryxNode` enum), visitor
  traits (`Visit`, `VisitMut`), span types. **Wraps oxc, never exposes it.**

- **`stryx_index`** owns: the project-level semantic index — symbol
  table, import graph, intra-file call graph, framework hints. Built
  once per scan; queried by rules and the taint engine. See
  [`docs/architecture/semantic-index.md`](docs/architecture/semantic-index.md).

- **`stryx_taint`** owns: the inter-procedural taint engine — `Source`,
  `Sink`, `Sanitizer` traits, taint labels, function summaries with
  content-keyed caching, bail-out logic that emits UncertainZones. See
  [`docs/architecture/taint-engine.md`](docs/architecture/taint-engine.md).

- **`stryx_rules`** owns: every shipped rule, organized as
  `sources/`, `sinks/`, `sanitizers/`, and `flows/` (per ADR 0003).
  Each rule implements the `Rule` trait and may declare a
  `taint_signature()` and `scope()` (single-file or cross-file).

- **`stryx_llm`** owns: the `LlmClient` trait, prompt templates per rule,
  retry logic, cost tracking. Pluggable: Anthropic, OpenAI, local Ollama.

- **`stryx_reporter`** owns: output format implementations.
  Pluggable: human text, JSON, SARIF, GitHub Actions annotations.

- **`stryx_cache`** owns: cache abstraction. In-memory (`dashmap`) for
  the active scan, on-disk persistence at `~/.cache/stryx/` for repeat
  local scans. Implementation behind a trait so alternative backends
  can be plugged in.

- **`stryx_cli`** owns: argument parsing, configuration loading, the
  binary entry point. Thin wrapper over `stryx_core`.

- **`stryx_napi`** owns: napi-rs bindings so `npm install stryx` ships
  the prebuilt Rust binary.

## The contract test

The single most important architectural property: **you can swap the parser
without touching the rules.**

This means:
- `stryx_ast` defines a normalized AST. Rules walk that AST, never oxc's.
- The parser adapter (currently `oxc_parser`) lives in `stryx_ast`.
- Rules in `stryx_rules` import only from `stryx_ast`, never from `oxc_*`.

We enforce this with a CI check:

```bash
# Fails if any rule crate imports from oxc_*
! grep -r "use oxc_" crates/stryx_rules/src/
```

If we ever want to swap to `swc_ecma_parser` or `biome_js_parser`, we
rewrite only the parser adapter. ~50 rules stay untouched.

## Concurrency model

Three layers, three different concurrency strategies:

- **Layer 1 (Parser)**: sequential within a file, parallel across files
  via `rayon`. Each file → its own arena allocator. No shared state.

- **Layer 2 (AST Rules)**: sequential within a file (visitor walks tree
  once, all rules see each node). Parallel across files via the same
  `rayon` pool from Layer 1.

- **Layer 3 (LLM)**: async/await with `tokio` for HTTP. Batched calls
  per scan to amortize latency. Backed by a content-hash cache.

The CLI is single-threaded `main()` that bridges sync (rayon) and async
(tokio) only at the LLM boundary. Don't sprinkle async through the AST
layer — it's CPU-bound, async adds complexity for no benefit.

## Performance budget

These are hard ceilings. Violations fail CI. Numbers must match
[CLAUDE.md "Performance budget"](CLAUDE.md#performance-budget) and
[`docs/architecture/rule-format.md`](docs/architecture/rule-format.md#performance-budget-per-rule).

| Layer / scope | Budget (p99) | Measured how |
|---|---|---|
| Single rule, single file | ≤ 1ms | criterion (per-rule bench) |
| Whole pipeline (parse + walk + all rules), 500-line TS file | ≤ 10ms | criterion |
| Layer 3 escalation per zone (cold) | ≤ 2s | integration test |
| Layer 3 escalation per zone (cached) | ≤ 5ms | integration test |
| Full scan, 10k files, no LLM | ≤ 30s | end-to-end test |
| Full scan, 10k files, with LLM (cold) | ≤ 90s | end-to-end test |

If a rule pushes the per-rule or whole-pipeline budget over, profile it
with `cargo flamegraph` and either optimize or move detection to Layer 3.

## Cache strategy

LLM calls are expensive. Cache aggressively.

**Cache key**: `blake3(zone_source + taint_summary + rule_id + prompt_hash + model_version)`

The `taint_summary` is the live label set and bail reason at the zone;
same syntactic zone in different taint contexts caches separately.
`prompt_hash` ensures prompt-iteration invalidates old cached answers
even when the model version is unchanged. See
[`docs/architecture/taint-engine.md`](docs/architecture/taint-engine.md#llm-escalation-interface).

**Cache value**: the LLM's structured response (JSON).

**Cache layers**:
1. In-process (`dashmap`) for the duration of a single scan
2. Local disk (`~/.cache/stryx/llm/`) for repeat local scans

**Invalidation**: implicit. Same content + same rule + same prompt
+ same model = same answer. If any input changes, the hash changes
and we recompute.

**Determinism mode**: `--no-llm` disables Layer 3 entirely. Output
is fully deterministic. Required for environments that need byte-stable
scan output across runs.

## Public API contracts (SemVer)

These break only on major version bumps:

- CLI flags and exit codes
- JSON output schema (each finding has `rule_id`, `severity`, `span`,
  `message`, `fix_hint?`, `confidence?`)
- SARIF output structure
- Rule IDs (e.g., `flow/unvalidated-body-to-db` is forever)
- The `Rule` trait signature in `stryx_rules`
- The `LlmClient` trait in `stryx_llm`

Internal: anything in `stryx_core::internal::*` is fair game to refactor.

## Failure modes and recovery

- **Parser fails on a file**: log, skip, continue. Other files still scan.
- **A rule panics**: the panic is caught per-rule, logged, treated as
  zero findings for that file. The scan completes.
- **LLM is unavailable**: Layer 3 results return as `inconclusive` with
  the original AST findings unchanged. Scan continues.
- **Cache is corrupted**: detect, clear, recompute. Never crash on cache.
- **Disk cache full or unwritable**: fall back to in-process-only
  caching for the scan; warn once per run.

## What we explicitly don't build (yet)

These are tempting but premature:

- **Microservices or daemons**: Stryx is a single CLI binary. Modules
  are the boundary, not services. There is no long-running server.
- **Custom rule DSL**: rules in Rust until we have 30+ rules. The
  abstraction is justified by repetition, not anticipation.
- **Full type-aware linting**: oxc's type-aware support is alpha;
  deferred to Phase 4. v0.1 uses scope info from `oxc_semantic` plus
  the project index; rules that need type flow emit UncertainZones.
- **Auto-fix**: we report issues; we don't rewrite code yet. Auto-fix is
  v2 once detection is mature.
- **Cross-package taint propagation**: we do not propagate taint
  through `node_modules`. Supply-chain analysis is a separate engine.

Cross-file analysis itself is **not** on this list — it's v0.1 core
per [ADR 0003](docs/decisions/0003-cross-file-and-taint-as-core.md).

[ADR 0001](docs/decisions/0001-rust-and-oxc.md) records why we chose Rust
and oxc over the alternatives.

## Open architectural questions

These don't have decisions yet. Track them in `docs/decisions/` as
they get resolved.

- How do we version rule outputs when a rule's detection logic
  improves (rule v1 caught X, v2 catches X+Y)?
- Plugin model for community rules: WASM plugins, Rust crate plugins
  (`cargo-deny` pattern), or both? What's the API surface?

### Resolved (linked to the ADR that closed each)

- ✅ Cross-file analysis as v0.1 core →
  [ADR 0003](docs/decisions/0003-cross-file-and-taint-as-core.md)
- ✅ Taint-aware LLM cache keys →
  [ADR 0005](docs/decisions/0005-taint-aware-cache-keys.md)
- ✅ Type-aware analysis: deferred to a later phase pending deeper
  `oxc_semantic` integration; not "if" but "when".
- ✅ Multi-language scope: TypeScript-only for the foreseeable
  roadmap; depth before breadth.

## When you're confused

1. Read `CLAUDE.md` for high-level conventions
2. Read this file for architecture
3. Look at `crates/stryx_rules/src/flows/unvalidated_body_to_db.rs` —
   the v0.1 reference flow rule (per ADR 0003)
4. Look at `docs/rules/_template.md` — the rule doc template
5. If still stuck, leave a `// TODO(human):` comment and ask
