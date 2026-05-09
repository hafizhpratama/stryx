# AST Pipeline

How a TypeScript project becomes a list of Findings.

> Reflects [ADR 0003](../decisions/0003-cross-file-and-taint-as-core.md):
> the index build (steps 3–5) is the load-bearing addition that makes
> cross-file analysis possible without holding every AST in memory.

## Overview

```
Project path
   │
   ▼
[1] Discovery       (ignore-aware traversal)
   │
   ▼
[2] Parse           (oxc_parser + oxc_semantic, per file, parallel)
   │
   ▼
[3] Index extract   (per file: symbols, imports, calls, framework hints)
   │
   ▼
[4] Free arena      (per-file arenas dropped after extraction)
   │
   ▼
[5] Project merge   (build cross-file structures: stryx_index)
   │
   ▼
[6] Analyze         (rules + taint engine query the index;
                     reparse on demand for cross-file zones)
   │
   ▼
[7] Emit            (Findings + UncertainZones)
   │
   ▼
[8] Escalate        (LLM analyzes UncertainZones)
   │
   ▼
[9] Report          (formatter writes output)
```

Steps 1–4 run in parallel across files via rayon.
Step 5 is single-threaded but cheap (hash-map merges).
Step 6 runs in parallel across files; rules query the shared index.
Step 8 is async, IO-bound, batched and cached.
Steps 7 and 9 are sync.

## Step 1 — File discovery

`stryx_core::discovery` uses the `ignore` crate (same as ripgrep) to
walk the project respecting:

- `.gitignore`
- `.stryxignore` (Stryx-specific overrides)
- Built-in defaults (`node_modules`, `dist`, `build`, `.next`, `coverage`)
- User config (`include` / `exclude` in `stryx.toml`)

Output: a flat `Vec<PathBuf>` of files to scan, ordered for predictable
benchmarking.

## Step 2 — Parse + Semantic + Normalize

For each file, in parallel via `rayon`:

```rust
let allocator = oxc_allocator::Allocator::default();
let source = std::fs::read_to_string(&path)?;
let source_type = oxc_span::SourceType::from_path(&path)?;
let ret = oxc_parser::Parser::new(&allocator, &source, source_type).parse();

let semantic = oxc_semantic::SemanticBuilder::new(&source, source_type)
    .build(&ret.program)
    .semantic;

let stryx_program = stryx_ast::from_oxc(&ret.program, &semantic);
```

Three sub-phases that share the per-file arena:

- **Parse**: `oxc_parser` produces the syntactic AST in the arena.
- **Semantic**: `oxc_semantic` resolves scopes and symbols. Used for
  recognizing imports (e.g., `z` from `zod`), tracking variable
  references across function bodies, and detecting unused symbols.
  ~1–2ms per file.
- **Normalize**: we wrap oxc's AST in `stryx_ast::Program`. The wrapper
  is thin — mostly zero-cost newtypes — but it's load-bearing for the
  parser-swap contract: rules in `stryx_rules` never import `oxc_*`.

The CI contract test enforces the wrap:

```bash
! grep -rE "use oxc_(parser|ast|semantic|allocator|span)" crates/stryx_rules/src/
```

If parsing fails (syntax errors), we log and skip the file. Other files
still scan.

## Step 3 — Index extract

A visitor walks the normalized AST once and emits index entries:

- `FileEntry` — content hash, source type, framework hint
- `SymbolEntry` — every top-level declaration
- `ImportEdge` — every `import` statement
- `CallSite` — every call expression
- `FrameworkHint` — heuristics + `package.json` + framework configs

Entries are small (~80–120 bytes each). They go into thread-local
accumulators that get merged in step 5. The full AST is not retained
beyond this step. See [`semantic-index.md`](semantic-index.md) for the
data model.

## Step 4 — Free arena

After index extraction completes for a file, the per-file
`oxc_allocator::Allocator` is dropped. Peak memory is bounded by
*active rayon threads*, not by total project size — typically one arena
per logical CPU during the parallel phase, all freed before step 5.

## Step 5 — Project merge

Single-threaded merge of per-file index entries into project-level
structures:

```rust
ProjectIndex {
    files,
    symbols,
    imports,
    callers,
    framework_hints,
}
```

This is a hash-map merge; cheap (~1s for 100k files). After this step,
the index is read-only and shareable across all rule analysis. Rules
hold `&ProjectIndex` for the rest of the pipeline.

## Step 6 — Analyze (rules + taint)

We walk each file's AST again (re-parsed lazily from cache) with all
enabled rules observing each node, plus the taint engine running
inter-procedural flow analysis using the project index:

```rust
let mut ctx = RuleContext::new(&index, &config);
for file_id in scan_files {
    let parsed = index.reparse(file_id)?;
    for node in parsed.walk() {
        for rule in &enabled_rules.matching(node.kind()) {
            rule.visit(node, &mut ctx);
        }
    }
    drop(parsed); // arena freed
}
taint_engine.analyze_project(&index, &mut ctx);
```

Rules register interest in specific node kinds (`fn interests()`) so
the dispatcher only invokes them on relevant nodes. Cross-file rules
declare `scope: CrossFile` and may walk the index; flow rules subscribe
to taint engine output rather than the AST visitor.

This means:
- Rule cost is additive within a node kind, not multiplicative across all rules
- Rules cannot interfere with each other (immutable index, immutable AST)
- Rule order doesn't matter
- Taint analysis runs once per project, not once per file

## Step 7 — Emit

During traversal, rules emit `Finding`s and `UncertainZone`s into the
`RuleContext`:

```rust
ctx.emit_finding(Finding { /* ... */ });
ctx.emit_uncertain(UncertainZone { /* ... */ });
```

These accumulate per file. After the walk, the per-file collection is
returned to `stryx_core`, which merges them with cross-file taint
flows emitted by `stryx_taint` (which used the project index from step 5).

## Step 8 — Escalation (optional)

If LLM escalation is enabled and the scan produced UncertainZones,
`stryx_core` batches them into LLM calls.

```rust
let zones = collect_uncertain_zones(&all_file_results);
let cache_hits = cache.lookup_batch(&zones);
let cache_misses = zones.subtract(&cache_hits);

let llm_results = llm_client.analyze_batch(&cache_misses).await?;
cache.insert_batch(&llm_results);

let escalated_findings = combine(cache_hits, llm_results)
    .filter(|r| r.confidence >= threshold)
    .map(into_finding);
```

Caching is by `blake3(zone_source + taint_summary + rule_id + prompt_hash + model_version)`.
Same content + same taint context + same rule + same prompt + same
model → same answer, free. See [`taint-engine.md`](taint-engine.md#llm-escalation-interface)
for why `taint_summary` and `prompt_hash` are part of the key.

## Step 9 — Reporting

The reporter receives the full `Vec<Finding>` and serializes per the
chosen format:

- `human` — colored CLI output with line/column annotations
- `json` — structured JSON for piping
- `sarif` — SARIF 2.1.0 for IDE / CI integration
- `github` — GitHub Actions annotations (`::warning::` etc.)

Reporters are pluggable. Add a new format by implementing the `Reporter`
trait in `crates/stryx_reporter`.

## Concurrency model

```
                  ┌─ Thread 1: file_a.ts (parse → analyze → emit)
                  ├─ Thread 2: file_b.ts (parse → analyze → emit)
rayon thread pool ┤
                  ├─ Thread N: file_n.ts (parse → analyze → emit)
                  └─ ...
                            │
                            ▼
                    Findings collector (sync, single-thread)
                            │
                            ▼
            UncertainZone batch (async, tokio runtime)
                            │
                            ▼
                    LLM client (async, retry, cache)
                            │
                            ▼
                    Final aggregation → Reporter
```

CPU-bound work uses `rayon` for data parallelism (one task per file).
IO-bound work (LLM calls) uses `tokio` async. The boundary is exactly
between Step 6 and Step 7 — nothing async happens before that.

## Memory model

- Each file's arena (oxc_allocator) is freed at step 4 — peak memory is
  bounded by the number of active rayon threads, not by project size.
- The project index (`stryx_index`) is the only persistent structure
  across steps 5–8. Index entries are small (~100 bytes/symbol);
  ~270MB resident for a 100k-file repo. See
  [`semantic-index.md`](semantic-index.md#memory-model).
- Function summaries cached by `stryx_taint` are ~100 bytes each;
  ~10MB for a 100k-LoC repo.
- On-demand re-parses in step 6 use a per-call arena that's dropped
  immediately after the rule finishes inspecting the file.
- Findings and UncertainZones are owned `String`/`Vec` allocations.
  Lifetime: until reporter writes them out.
- The LLM cache is the only long-lived per-process state outside the
  index, capped at ~100MB.

A 100k-file monorepo scan typically peaks around ~600MB resident,
dominated by the index + active per-thread arenas.

## Error handling per file

If anything fails for a single file, we log a warning and skip it:

- Parse errors → log, skip
- Encoding errors → log, skip
- Permission denied → log, skip
- A rule panics → catch, log, treat as zero findings for that file

The scan completes regardless. The CLI exits non-zero only if findings
above the threshold are emitted, OR if more than 5% of files failed to
process (configurable via `--max-skip-rate`).

## What this pipeline does NOT do

- **Full type checking** — We do not run TypeScript's type checker.
  Steps 2–3 use oxc's syntactic + scope analysis (`oxc_semantic`).
  Full type-aware analysis is Phase 4 work; until then, rules that
  need type flow emit UncertainZones for LLM escalation.
- **Cross-package taint propagation** — We do not propagate taint
  through `node_modules`. Function calls into installed packages are
  treated as opaque. Supply-chain analysis is a separate engine.
- **Auto-fix** — We report; we don't rewrite. Auto-fix is v2.
- **Incremental scans** — Every scan is full. Incremental scans (only
  changed files) require LSP-style integration; on the roadmap, not v0.1.

Cross-file analysis itself is **done** by this pipeline as of v0.1
(per [ADR 0003](../decisions/0003-cross-file-and-taint-as-core.md));
the project index in step 5 is the load-bearing addition.

## Profiling tips

```bash
# Flamegraph the entire pipeline on a real repo
cargo flamegraph --bin stryx -- scan ./big-fixture

# Time individual rules
cargo bench --bench rules

# Detailed tracing
RUST_LOG=stryx=trace cargo run --bin stryx -- scan ./fixture

# Memory profile
cargo run --bin stryx -- scan ./big-fixture
# (then heaptrack or valgrind massif on the binary)
```
