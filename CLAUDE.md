# Stryx — AI Context

> This file is read by Claude Code (and other AI agents) at the start of every
> session. Keep it accurate. Update it whenever architecture, conventions, or
> commands change. If this file lies, the AI lies.
>
> Last reviewed: 2026-05-14 (v0.2.1)

## What Stryx is

Stryx is a Rust-based static analyzer that catches AI-generated code failures
in TypeScript before they ship to production. It targets the specific failure
patterns that Cursor, Claude Code, GitHub Copilot, and similar tools commonly
produce — missing input validation, hardcoded secrets, weak auth, missing rate
limits, etc.

**Tagline:** Sees what your AI missed.

**Audience (in priority order):**
1. Solo indie devs / vibe coders shipping AI-generated TypeScript
2. Small teams (2–20 devs) using AI coding tools daily
3. Mid-size companies (later, after PMF)
4. Enterprise (year 2+, only after community traction)

**Distribution channels:** npm (via napi-rs), Homebrew, Cargo, GitHub Action,
Vercel/Netlify pre-deploy hook.

## Why Stryx exists

In 2026, ~41% of code globally is AI-generated and ~45% of it ships
with vulnerabilities.[^stats] AI coding tools commonly produce code
that handles untrusted input, secrets, or auth in ways that look
plausible but skip runtime safety checks.

The hardest of these patterns to catch are flows that span multiple
files — a route handler that hands off to a helper module that does
the unsafe operation, with no validator anywhere along the path.

Stryx targets these cross-file flows in TypeScript specifically.
Rust + oxc keeps the engine fast; cross-file taint analysis is the
core technique; LLM escalation is reserved for the small subset of
zones where the engine genuinely cannot decide statically.

## Architecture (3 layers)

```
┌──────────────────────────────────────────────┐
│  LAYER 3: LLM Semantic Analysis (slow, deep) │
│  Runs only on uncertain zones flagged by L2  │
│  Cached by content hash. Opt-in; deterministic
│  mode disables it for reproducible CI.       │
├──────────────────────────────────────────────┤
│  LAYER 2: Rust AST Pattern Detection (fast)  │
│  Deterministic rules running on every file.  │
│  Emits Findings AND UncertainZones.          │
├──────────────────────────────────────────────┤
│  LAYER 1: Rust Parser (oxc, MIT-licensed)    │
│  TS source → arena-allocated AST             │
└──────────────────────────────────────────────┘
```

The differentiator is **cross-file taint analysis with LLM-confirmed
intent** (see [ADR 0003](docs/decisions/0003-cross-file-and-taint-as-core.md)).
The AST + LLM hybrid is the mechanism, but the load-bearing technique
is inter-procedural taint with content-keyed function summaries, plus
LLM escalation reserved for genuinely ambiguous zones.

- AST-only analysis misses cross-file flow and semantic intent.
- LLM-only analysis trades latency and per-call cost for intent
  reasoning; non-deterministic by design and not built to see project
  structure across files.
- Stryx: most issues caught in milliseconds by AST + index queries;
  the genuinely ambiguous zones are escalated to a cached LLM check.
  LLM cost is bounded by aggressive content-hash caching.

## Tech stack

- **Language:** Rust 1.93+, edition 2024 (toolchain pinned in `rust-toolchain.toml`)
- **Parser:** `oxc_parser`, `oxc_ast`, `oxc_semantic` 0.129.x (MIT)
- **Concurrency:** `rayon` for file-level parallelism (sync within file)
- **Cache:** `dashmap` in-memory for the active scan; on-disk SQLite
  at `~/.cache/stryx/` for repeat scans
- **HTTP/LLM:** `reqwest` + `rustls` (Layer 3 only)
- **Observability:** `tracing` (vendor-neutral)
- **Bench:** `criterion`
- **CLI:** `clap`
- **File traversal:** `ignore` (gitignore-aware, same as ripgrep)
- **npm distribution:** `napi-rs` (prebuilt binaries via npm)
- **Serialization:** `serde` + `serde_json`

## Workspace layout

This is the canonical layout. `ARCHITECTURE.md` and `.github/copilot-instructions.md`
must match.

```
stryx/
├── crates/
│   ├── stryx_core/        # Scan orchestration, pipeline, public API
│   ├── stryx_ast/         # Normalized AST + visitor traits
│   ├── stryx_index/       # Project semantic index (ADR 0003)
│   ├── stryx_taint/       # Inter-procedural taint engine (ADR 0003)
│   ├── stryx_rules/       # Source/sink/sanitizer/flow rules
│   │   └── src/
│   │       ├── sources/   # Taint sources (HTTP, env, fs, network)
│   │       ├── sinks/     # Taint sinks (DB, exec, response, log)
│   │       ├── sanitizers/# Validators, escapers, auth checks
│   │       └── flows/     # Cross-cutting taint rules
│   ├── stryx_llm/         # Layer 3 escalation client + prompts
│   ├── stryx_reporter/    # JSON, SARIF, text, GitHub annotations
│   ├── stryx_cache/       # Content-hash cache abstraction
│   ├── stryx_cli/         # Binary (clap-based)
│   └── stryx_napi/        # napi-rs bindings for npm distribution
├── plugins/               # Future: WASM rule plugins
├── benches/               # Criterion benchmarks
├── xtask/                 # Custom build tasks
└── docs/
    ├── rules/             # One md file per rule
    ├── architecture/      # Deep design docs
    └── decisions/         # ADRs
```

## Conventions and rules

### Hard rules (don't violate)

1. **Don't expose oxc types in public API.** Always wrap them in `stryx_ast`.
   This keeps the parser swappable. Test: can we replace oxc_parser with
   swc_ecma_parser without touching `stryx_rules`? If no, the AST is leaky.

2. **Async only at the LLM client boundary.** AST traversal and
   index construction are CPU-bound. Async adds complexity for no
   benefit. Use `tokio` only in `stryx_llm` for HTTP calls.

3. **Don't use `Box<dyn Trait>` in hot paths.** Use enum dispatch for rules
   and AST nodes. Profile before assuming dyn is fine. The single allowed
   exception is the rule registry (`crates/stryx_rules/src/registry.rs`),
   which is built once at startup and never traversed in a hot loop.

4. **Don't add `Arc<Mutex<_>>` patterns.** Use `dashmap` for shared concurrent
   state, or message passing via `crossbeam-channel`.

5. **No rule DSL until 30+ rules exist.** Keep rules in Rust for now.
   A YAML/declarative DSL is a v2 feature once the abstraction is justified
   by repetition. oxlint did the same — Rust rules first, plugins later.

6. **Every rule has a real-world test fixture.** When you add a rule, you
   add `tests/fixtures/<rule-id>/bad.ts` with real AI-generated code that
   triggers it, plus `good.ts` that doesn't. Rules live under
   `crates/stryx_rules/src/{sources,sinks,sanitizers,flows}/<rule_id>.rs`
   per ADR 0003. Most user-visible rules are flow rules.

7. **Track perf from day one.** Each rule has a criterion bench. CI fails
   if scan time per KLOC regresses by more than 10% on the integration suite.

8. **Layer 3 is opt-in and cacheable.** The default engine runs
   without LLM unless explicitly enabled — bring your own API key for
   Layer 3, or run with `--no-llm` for fully local deterministic
   scans. Cache LLM responses by
   `blake3(zone_source + taint_summary + rule_id + prompt_hash + model_version)`
   per [ADR 0005](docs/decisions/0005-taint-aware-cache-keys.md). The
   taint context is part of the key because the same syntactic zone
   in different taint contexts has different verdicts. Same content +
   same context = same answer.

9. **Don't break public APIs without a major version bump.** SemVer strict.
   Internal refactors are free; CLI flags, JSON output schema, and rule IDs
   are public contracts.

### Soft conventions (prefer, but pragmatic)

- Prefer `&str` over `String` in hot paths; oxc allocates strings in an arena.
- Prefer `match` over `if let` chains.
- Use `thiserror` for library errors, `anyhow` only at binary boundaries.
- Use `tracing::instrument` on public functions for free observability.
- Tests live next to source via `#[cfg(test)] mod tests` for unit tests;
  integration tests in `tests/` for end-to-end scans.

## Common commands

```bash
# Local development
cargo run --bin stryx -- scan ./fixtures/nextjs-app
cargo test --workspace
cargo bench --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check

# napi-rs (npm package)
cd crates/stryx_napi
npm run build
npm test

# Profiling
cargo flamegraph --bin stryx -- scan ./large-fixture
```

## Adding a new rule

The single most common task. Follow this exact flow:

1. **Find the failure in the wild.** Take a real Cursor/Claude Code/Copilot
   output that has the bug. Save it to `tests/fixtures/<rule-id>/bad.ts`.
2. **Write the doc first.** Create `docs/rules/<category>-<rule-id>.md`
   (e.g. `flow-unvalidated-body-to-db.md`) following the rule template
   (see `docs/rules/_template.md`). This forces clarity before you
   write code.
3. **Implement the rule** under
   `crates/stryx_rules/src/{sources,sinks,sanitizers,flows}/<rule_id>.rs`
   (most rules go in `flows/`; primitives go in their respective folders).
   Implement the `Rule` trait. Declare `taint_signature()` and `scope()`
   per ADR 0003. Return `Vec<Finding>` and optionally
   `Vec<UncertainZone>` for LLM escalation.
4. **Add a `good.ts` fixture** showing the correct version.
5. **Write integration test** in `tests/rules.rs` asserting findings on
   `bad.ts` and zero findings on `good.ts`.
6. **Add criterion bench** in `benches/rules.rs`.
7. **Register the rule** in `crates/stryx_rules/src/registry.rs`.
8. **Update CHANGELOG.md.**

The doc-first flow matters: it makes you decide what the rule actually
catches, in plain language, before writing any matching logic.

## What NOT to do

- **Don't fork oxc.** Depend on it as a crate. Upstream improvements
  flow to us automatically; forking creates open-ended maintenance debt.
- **Don't copy Semgrep rules.** Their license restricts use in
  competing products. Use OWASP and CWE catalogs for pattern
  references; write detection from scratch in our format.
- **Don't add a UI to the CLI.** The CLI stays scriptable. Any UI work
  belongs outside this repo.
- **Don't add Kubernetes, Kafka, or microservices.** A single binary
  is enough for the engine; add complexity only when forced.
- **Don't hardcode the LLM provider.** Use the `LlmClient` trait so
  Anthropic, OpenAI, local Ollama, and others can be swapped freely.
- **Don't write rules that depend on full type inference yet.**
  Type-aware linting in oxc is alpha; deeper integration is Phase 4
  per the roadmap. v0.1-v0.2 rules use syntactic analysis, scope
  info from `oxc_semantic`, the project semantic index
  (`stryx_index`), and the taint engine (`stryx_taint`). When a rule
  genuinely needs type flow, emit an UncertainZone for LLM
  escalation rather than guessing.

## File map (where to look)

- `ARCHITECTURE.md` — deep design decisions, contract tests, AST schema
- `docs/architecture/rule-format.md` — how rules are structured
- `docs/architecture/llm-escalation.md` — when and how Layer 3 fires
- `docs/architecture/ast-pipeline.md` — parsing → analysis → reporting
- `docs/rules/` — every shipped rule has a markdown doc here
- `docs/decisions/` — ADRs (Architecture Decision Records), dated
- `docs/glossary.md` — definitions of pattern/rule/finding/zone/escalation
- `crates/stryx_rules/README.md` — rule catalog. Read before adding rules.
- `crates/stryx_taint/README.md` — taint engine. The core analysis primitive (with `stryx_index`).
- `crates/stryx_index/README.md` — project semantic index.
- `crates/stryx_ast/README.md` — normalized AST. Read before touching.
- `docs/architecture/taint-engine.md` — taint engine design
- `docs/architecture/semantic-index.md` — index design
- `THIRD_PARTY_LICENSES.md` — every dep + its license

## Glossary (terms with exact meanings)

- **Pattern** — a class of bug we catch (e.g., "missing input validation")
- **Rule** — the implementation of a Pattern in Rust + its docs
- **Finding** — a concrete instance of a rule firing on real code
- **Zone** — a span of source code (file + start byte + end byte)
- **UncertainZone** — a Zone that AST rules flag for LLM escalation
- **Escalation** — Layer 3 LLM analysis of an UncertainZone
- **Severity** — info, low, medium, high, critical (used in CLI exit codes)
- **Confidence** — 0.0–1.0, only meaningful for LLM-derived findings

These mean exactly one thing each. If you find them used otherwise, fix it.

## Performance budget

These numbers are normative. `ARCHITECTURE.md` repeats them; the per-rule
budget also lives in `docs/architecture/rule-format.md`.

| Layer / scope | Budget (p99) |
|---|---|
| Single rule, single file | ≤ 1ms |
| Whole pipeline (parse + walk + all rules), single 500-line TS file | ≤ 10ms |
| Layer 3 escalation per zone (cold) | ≤ 2s |
| Layer 3 escalation per zone (cached) | ≤ 5ms |
| Full repo scan, 10k files, no LLM | ≤ 30s |
| Full repo scan, 10k files, with LLM (cold cache) | ≤ 90s |
| CI overhead on a typical Next.js repo | < 60s |

If you write a rule that exceeds these, profile it before merging.

## License and legal

- Stryx is licensed under **Apache 2.0** — permissive, with no plans
  to change.
- All dependencies are tracked in THIRD_PARTY_LICENSES.md.
- We use only permissively-licensed dependencies (MIT, Apache 2.0,
  BSD, ISC, similar). No GPL, LGPL, AGPL, BSL, SSPL, or other
  copyleft / source-available code.
- We do not copy detection rules from other projects. Patterns are
  written from scratch using OWASP, CWE, and our own analysis of real
  AI output as references.

## Roadmap context

Reflects [ADR 0003](docs/decisions/0003-cross-file-and-taint-as-core.md)
(cross-file taint as v0.1 core).

- **Phase 1 (v0.1)** ✅ shipped — TypeScript-only, Next.js-aware.
  Foundational crates `stryx_index` and `stryx_taint`. Three stable
  cross-file flow rules: `flow/unvalidated-body-to-db`,
  `flow/auth-bypass-via-wrapper`, `flow/secret-to-response`. CLI +
  pre-built binaries.
- **Phase 2 (v0.2, v0.2.1)** ✅ shipped — 7 new rules vs. v0.1.
  Cross-file slice 2 for SSRF, redirect-open, SQL-injection, and
  command-injection (all Critical-severity rules now cross-file).
  Single-file slice 1 for path-traversal, prompt-injection, XSS.
  App Router `searchParams.X` body-source recognition. SSRF
  host-pinning precision (env-var-prefix templates → Medium
  path-injection). 10 rules in the registry. See
  [ADR 0011](docs/decisions/0011-v01-to-v02-transition.md) for the
  Phase 2 plan + retrospective.
- **Phase 3** 🚧 in-progress — Hono and Express via source/sink
  adaptations (not rule rewrites). Suppression-density meta-rule.
  napi-rs npm distribution. GitHub Action. Homebrew formula.
  WASM/crate plugin model (decision pending).
- **Phase 4** 📋 deferred — Type-aware analysis via deeper
  `oxc_semantic` use. Custom taint configs (project-specific
  sources/sinks via `stryx.toml`). Framework version dimension on
  rules. Cross-file slice 2 for the remaining single-file rules
  (prompt-injection, XSS) once OSS sweep surfaces TPs.

Don't build later-phase features in earlier-phase code. Resist
scope creep. Depth in the taint engine and the rule library matters
more than framework count — depth before breadth.

## When in doubt

- Read `ARCHITECTURE.md` first
- Then `docs/rules/_template.md` for rule format
- Then look at the v0.1 reference flow rule
  (`crates/stryx_rules/src/flows/unvalidated_body_to_db.rs`) for how
  source/sink/sanitizer + cross-file taint compose into a finding
- If still unclear, leave a `// TODO(claude):` comment with the question
  and surface it to the human in your summary

## Contact and maintenance

- Maintainer: Hafizh Pratama
- Repo: github.com/hafizhpratama/stryx
- Docs site: stryx.dev
- Security disclosures: security@stryx.dev (see SECURITY.md)

[^stats]: 41% AI-generated code figure: daily.dev 2026 developer trends
    report. 45% AI-code vulnerability rate: ACM communications, April 2026
    ("Security Implications of AI-Generated Code"). Refresh with primary
    URLs and newer surveys as they publish.
