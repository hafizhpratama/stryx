# GitHub Copilot Instructions

GitHub Copilot reads this file at `.github/copilot-instructions.md`
by convention. The **single source of truth** for AI-agent context
in this repository is [`AGENTS.md`](../AGENTS.md) at the repo root.
Read that for project context, tech stack, hard rules, conventions,
the workspace layout, the rule-authoring workflow, and the performance
budget.

If you only take one thing from this file: **read `AGENTS.md`
before making any non-trivial change.** A short orientation
follows; consult `AGENTS.md` for anything beyond.

- **Project** — Stryx, a Rust static analyzer that catches AI-
  generated JavaScript/TypeScript backend security failures before they ship.
- **Boundary** — stack-aware backend/platform security, not React hooks,
  component architecture, accessibility, UI style, or generic code quality.
- **Stack** — Rust 1.93+ (edition 2024), `oxc_parser` 0.129.x for
  TS parsing, `rayon` for file-level parallelism, `tokio` only at
  the LLM HTTP boundary, `dashmap` for shared concurrent state.
- **License** — Apache 2.0. Don't import GPL / LGPL / AGPL / SSPL
  / BSL code. Don't copy Semgrep rules.
- **Anti-patterns** — no `Box<dyn>` in hot paths, no async in AST
  analysis, no rule DSL until 30+ rules exist, no forking oxc.
- **Rule docs** — every rule doc is a fix guide with `How to fix` and
  `What Stryx recognizes`; avoid vague "best practice" language.

For everything else — workspace layout, the `Rule` trait shape,
the rule-authoring workflow, the file map, the glossary, the
performance budget — see [`AGENTS.md`](../AGENTS.md) and
[`ARCHITECTURE.md`](../ARCHITECTURE.md).
