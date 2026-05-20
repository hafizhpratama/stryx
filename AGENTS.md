# AGENTS.md

> Single source of truth for AI agents working in this repository.
> Claude-specific and Copilot-specific files should point here instead
> of duplicating project instructions.

## Product boundary

Stryx is a stack-aware security scanner for JavaScript and TypeScript
backend/platform code. It catches production-risk flows that commonly
appear in modern backend stacks:

- missing runtime validation before database writes
- auth wrappers that do not actually enforce auth
- secrets in responses or hardcoded in source
- SSRF and open redirects
- SQL injection and command injection
- filesystem path traversal
- unsafe LLM prompt handling

The current direction is **stack-aware TypeScript backend/platform
security**. Stryx should detect project stack evidence, enable adapters,
and keep vulnerability rules generic.

Out of scope:

- React hooks and component architecture
- rendering performance
- accessibility linting
- Tailwind/style cleanup
- bundle-size style advice
- broad subjective code quality

Next.js support is allowed for backend surfaces only: route handlers,
server actions, middleware, auth, database calls, and server/runtime
boundaries.

## Architecture snapshot

```text
JavaScript / TypeScript source
  ↓
Project profile (planned): runtime/framework/data/auth/LLM evidence
  ↓
Layer 1: oxc parser
  ↓
Layer 2: project index + stack adapters + AST rules + taint engine
  ↓
Layer 3: optional cached LLM escalation for uncertain zones
  ↓
Findings + fix hints + rule docs
```

Key docs:

- [`ARCHITECTURE.md`](ARCHITECTURE.md)
- [`docs/architecture/project-profile.md`](docs/architecture/project-profile.md)
- [`docs/architecture/stack-adapters.md`](docs/architecture/stack-adapters.md)
- [`docs/product/stack-aware-cli.md`](docs/product/stack-aware-cli.md)
- [`docs/roadmap/stack-aware-scanning.md`](docs/roadmap/stack-aware-scanning.md)
- [`docs/stacks/README.md`](docs/stacks/README.md)
- [`docs/rules/_template.md`](docs/rules/_template.md)

## Tech stack

- Rust 1.93+, edition 2024
- `oxc_parser`, `oxc_ast`, `oxc_semantic` for JS/TS parsing
- `rayon` for file-level CPU parallelism
- `tokio` only at the LLM HTTP boundary
- `dashmap` for shared concurrent state
- `clap` for the CLI
- `ignore` for gitignore-aware traversal
- `serde` / `serde_json` for reports and public schemas
- `napi-rs` for npm distribution

## Engineering rules

- Do not expose `oxc_*` types through public Stryx APIs.
- Keep async at the LLM/client boundary, not in AST traversal.
- Avoid `Box<dyn Trait>` in hot paths; enum dispatch is preferred.
- Do not add a rule DSL until repetition justifies it.
- Do not copy Semgrep rules or code from incompatible licenses.
- Do not add React/client UI quality rules.
- Preserve public contracts: CLI flags, JSON schema, rule IDs, adapter IDs.
- Rules need real fixtures, good fixtures, integration tests, docs, and
  benchmarks.
- Prefer `thiserror` for library errors and `anyhow` at binary
  boundaries.
- Prefer deterministic local analysis. LLM escalation is optional,
  cached, and only for genuinely uncertain zones.
- Do not make network calls, install dependencies, or call an LLM during
  project-profile detection.

## Workspace map

- `crates/stryx_ast` — parser boundary and AST visitor exports
- `crates/stryx_index` — project semantic index and planned profile layer
- `crates/stryx_taint` — taint labels, summaries, and flow primitives
- `crates/stryx_rules` — shipped rules, steps, and future adapters
- `crates/stryx_cli` — CLI scan orchestration
- `crates/stryx_reporter` — human/JSON/SARIF/GitHub output
- `crates/stryx_llm` — optional Layer 3 clients/prompts
- `docs/rules` — one public rule doc per shipped rule
- `docs/decisions` — ADRs; append new decisions instead of rewriting
  history

## Rule docs

Every rule doc is a fix guide. It must include:

- `How to fix`
- `What Stryx recognizes`
- `Taint signature`
- `Known false positive zones`
- `Suppressing this rule`

Avoid vague "best practice" language. State the concrete safe pattern and
what the analyzer currently accepts as fixed.

## Adding or changing rules

Use the doc-first flow:

1. Start from a real backend security failure pattern.
2. Add a bad fixture under `tests/fixtures/<rule-id>/`.
3. Add a good fixture showing the safe version.
4. Write or update the rule doc using `docs/rules/_template.md`.
5. Implement the rule or adapter change.
6. Add/update integration tests.
7. Add/update a criterion bench for rule hot paths.
8. Register the rule or adapter.
9. Update `CHANGELOG.md`.

For adapter work, keep the vulnerability rule generic. Add stack-specific
sources, sinks, sanitisers, and guards through the adapter substrate.

## Stack-aware adapter direction

Rules stay generic:

- `flow/unvalidated-body-to-db`
- `flow/sql-injection`
- `flow/command-injection-via-exec`
- `flow/ssrf-via-fetch`
- `flow/redirect-open`
- `flow/path-traversal`
- `flow/prompt-injection`

Adapters contribute stack facts:

- `runtime/bun`
- `framework/hono`
- `framework/express`
- `data/drizzle`
- `validation/zod`
- `auth/better-auth`
- `llm/openai`

Do not create framework-specific forks of vulnerability rules unless the
semantics are genuinely different.

## Performance Budget

These budgets are normative for implementation work:

| Layer / scope | Budget |
|---|---|
| Single rule, single file | <= 1 ms p99 |
| Whole pipeline, 500-line JS/TS file | <= 10 ms p99 |
| Full scan, 10k files, no LLM | <= 30 s |
| Full scan, 10k files, cold LLM | <= 90 s |
| LLM escalation per zone, cold | <= 2 s |
| LLM escalation per zone, cached | <= 5 ms |

If a change touches hot paths, run or add a benchmark. Do not assume a
new abstraction is free.

## License and Sources

- License: Apache 2.0.
- Use permissively licensed dependencies only.
- Do not import GPL, LGPL, AGPL, SSPL, BSL, or similar source-available
  code.
- Do not copy Semgrep rules. Implement patterns from scratch using OWASP,
  CWE, official framework docs, and minimal reproductions.
- Fixtures must be written by you or otherwise redistributable under the
  repository license.

## Common commands

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p stryx_cli -- scan ./tests/fixtures/flow-sql-injection/bad.ts
```

## Before finishing work

- Check `git status --short`.
- Run tests or explain why they were not run.
- For docs-only changes, inspect changed markdown headings and links.
- Mention any public contract changes explicitly.
