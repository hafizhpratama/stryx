# GitHub Copilot Instructions

This file is read by GitHub Copilot when working in this repository. It
mirrors the essential conventions from `CLAUDE.md`, which is the single
source of truth. If this file and `CLAUDE.md` disagree, **`CLAUDE.md`
wins** — and the divergence is a bug worth filing.

For full context, read `CLAUDE.md` and `ARCHITECTURE.md`.

## Project

Stryx is a Rust static analyzer that catches AI-generated code failures
in TypeScript before they ship.

## Tech stack

- Rust 1.93+, edition 2024, Cargo workspace (channel pinned in `rust-toolchain.toml`)
- `oxc_parser` 0.129.x (MIT) for TS parsing — depend on it, never fork
- `rayon` for file-level parallelism
- `tokio` only at the LLM HTTP boundary (`stryx_llm`)
- `dashmap` in-memory + `rusqlite` on-disk caches
- `napi-rs` for npm distribution

## Architecture (3 layers)

1. Parser (oxc) → AST
2. AST rules (Rust, deterministic) → Findings + UncertainZones
3. LLM escalation (optional, cached) → confirms UncertainZones

## Hard rules

1. Don't expose `oxc_*` types in the public API. Always wrap in `stryx_ast`.
2. No async in AST analysis (CPU-bound). `tokio` only in `stryx_llm`.
3. No `Box<dyn Trait>` in hot paths. Use enum dispatch.
4. No rule DSL until 30+ rules exist. Keep rules in Rust.
5. Every rule has a real-world test fixture (`tests/fixtures/<rule-id>/`).
6. Rule IDs are stable forever once shipped.
7. Layer 3 must be opt-in (`--no-llm` for deterministic CI).

## Anti-patterns

- Don't use `unwrap()` in non-test code.
- Don't add `Arc<Mutex<_>>` patterns. Use `dashmap` or message passing.
- Don't copy Semgrep rules (license forbids commercial use).
- Don't add Kubernetes / Kafka / microservices yet.
- Don't add type-aware linting yet (oxc support is alpha).

## When adding a rule

1. Find the failure in real AI output (Cursor, Claude Code, Copilot, etc.)
2. Save real bad code to `tests/fixtures/<rule-id>/bad.ts` with
   attribution comment
3. Write the doc first: `docs/rules/<category>-<rule-id>.md`
   (e.g. `flow-unvalidated-body-to-db.md`)
4. Implement under `crates/stryx_rules/src/{sources,sinks,sanitizers,flows}/<rule_id>.rs`
   (most rules go in `flows/`; primitives go in their respective folders) per ADR 0003
5. Add `good.ts` fixture
6. Add integration test in `tests/rules.rs`
7. Add criterion bench in `benches/rules.rs`
8. Register in `crates/stryx_rules/src/registry.rs`
9. Update CHANGELOG.md

## Glossary

- **Pattern** — a class of bug we want to catch (concept)
- **Rule** — the implementation of a Pattern (Rust code)
- **Finding** — an instance of a Rule firing (output)
- **Zone** — a code region (file + byte range)
- **UncertainZone** — Zone flagged by AST for LLM review
- **Escalation** — LLM analyzing an UncertainZone
- **Severity** — info / low / medium / high / critical
- **Confidence** — 0–1, only for LLM-derived findings

## Common commands

```bash
cargo run --bin stryx -- scan <path>
cargo test --workspace
cargo bench --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

## License

Apache 2.0. Don't import GPL/LGPL/AGPL/SSPL/BSL code.

## More context

- `CLAUDE.md` — full AI agent context
- `ARCHITECTURE.md` — design deep dive
- `CONTRIBUTING.md` — workflow for contributors
- `docs/rules/_template.md` — rule doc template
- `docs/glossary.md` — term definitions
