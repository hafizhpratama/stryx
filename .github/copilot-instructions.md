# GitHub Copilot Instructions

GitHub Copilot reads this file at `.github/copilot-instructions.md`
by convention. The **single source of truth** for AI-agent context
in this repository is [`CLAUDE.md`](../CLAUDE.md) at the repo root.
Read that for project context, tech stack, hard rules, conventions,
the workspace layout, the rule-authoring workflow, and the
performance budget.

If you only take one thing from this file: **read `CLAUDE.md`
before making any non-trivial change.** A short orientation
follows; consult `CLAUDE.md` for anything beyond.

- **Project** — Stryx, a Rust static analyzer that catches AI-
  generated code failures in TypeScript before they ship.
- **Stack** — Rust 1.93+ (edition 2024), `oxc_parser` 0.129.x for
  TS parsing, `rayon` for file-level parallelism, `tokio` only at
  the LLM HTTP boundary, `dashmap` for shared concurrent state.
- **License** — Apache 2.0. Don't import GPL / LGPL / AGPL / SSPL
  / BSL code. Don't copy Semgrep rules.
- **Anti-patterns** — no `Box<dyn>` in hot paths, no async in AST
  analysis, no rule DSL until 30+ rules exist, no forking oxc.

For everything else — workspace layout, the `Rule` trait shape,
the rule-authoring workflow, the file map, the glossary, the
performance budget — see [`CLAUDE.md`](../CLAUDE.md) and
[`ARCHITECTURE.md`](../ARCHITECTURE.md).
