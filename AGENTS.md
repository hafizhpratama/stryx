# Stryx — AI Agent Context

This file is the vendor-neutral entry point for AI coding agents working in
this repository. It is a thin pointer to `CLAUDE.md`, which is the single
source of truth.

If `AGENTS.md`, `CLAUDE.md`, and `.github/copilot-instructions.md` ever
diverge, **`CLAUDE.md` wins** and the others should be updated to match.
Symlinking AGENTS.md → CLAUDE.md is tempting but breaks on Windows and
some Git hosts; we keep them in sync manually until an `xtask` job
automates it.

For the full project context — architecture, conventions, rules for adding
features, glossary, performance budget, anti-patterns — see:

- **[CLAUDE.md](CLAUDE.md)** — primary AI context
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — deep design
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — workflow for code changes
- **[docs/glossary.md](docs/glossary.md)** — exact term definitions
- **[docs/rules/_template.md](docs/rules/_template.md)** — rule doc format

## Quick orientation for any AI agent

- **Project**: Stryx, a Rust static analyzer for AI-generated TypeScript
- **Language**: Rust 1.93+ (workspace, edition 2024; pinned in `rust-toolchain.toml`)
- **Parser**: `oxc_parser` (MIT) — depend on it, do not fork
- **Architecture**: 3 layers — parser, AST rules, optional LLM escalation
- **License**: Apache 2.0
- **Anti-patterns**: no `Box<dyn>` in hot paths; no async in AST; no rule
  DSL until 30+ rules; no copying Semgrep rules

If you take only one thing from this file: **read `CLAUDE.md` before
making any non-trivial change.**
