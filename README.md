# Stryx

> Sees what your AI missed — across files.

A Rust static analyzer for AI-generated TypeScript. Stryx catches the
specific failure patterns AI coding tools commonly produce — missing
input validation, leaked secrets, weak auth, missing rate limits —
using cross-file taint analysis with optional LLM-confirmed intent on
genuinely ambiguous flows.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange.svg)](#status)

## Why

In 2026, ~41% of code is AI-generated and ~45% of it ships with
vulnerabilities.[^stats] AI coding tools (Cursor, Claude Code, GitHub
Copilot, v0, Lovable, and others) frequently scaffold code that
handles untrusted input, secrets, or auth in ways that look plausible
but skip the runtime safety checks production needs.

The hardest patterns to catch are flows that span multiple files — a
route handler in `app/api/.../route.ts` that passes `req.json()`
directly into a helper module's database write, with no validator
anywhere along the path. Single-file linters can't see the disconnect.
Reviewers may miss it. Tests rarely cover the malicious-payload case.

Stryx is built specifically for these cross-file flows in TypeScript.
The engine runs in milliseconds (Rust + oxc), produces deterministic
findings on the AST and project-index pass, and escalates only the
small subset of genuinely ambiguous zones to a cached LLM check.

## Install

From source — works today:

```bash
git clone https://github.com/hafizhpratama/stryx
cd stryx
cargo install --path crates/stryx_cli
```

Pre-built binaries — attached to the [v0.1.0 GitHub Release](https://github.com/hafizhpratama/stryx/releases/tag/v0.1.0)
across five targets (Linux x64/arm64, macOS x64/arm64, Windows x64).

Cargo (`cargo install stryx-cli`), npm (`npx stryx scan`), and Homebrew
(`brew install stryx/tap/stryx`) distribution channels follow once
the npm namespace + Homebrew tap repo are set up.

## First scan

```bash
cd your-typescript-project
stryx scan
```

You'll get findings like:

```
✗ flow: app/api/users/route.ts → lib/users.ts:4:3
  [high] flow/unvalidated-body-to-db
  Untrusted body reaches db.user.create unsanitized; flow crosses 2 files.
  → Validate the body with zod/valibot/yup at the entry handler before
    passing it to lib/users.ts:createUser
  Read more: https://stryx.dev/rules/flow-unvalidated-body-to-db
```

The CLI exits non-zero when findings at or above the configured
severity threshold are emitted, so it works as a CI gate.

## What Stryx catches

Three v0.1 rules demonstrating cross-file taint analysis:

- **`flow/unvalidated-body-to-db`** — request body flows to a database
  write without zod, valibot, ajv, joi, or yup along the path, even
  when the flow crosses files.
- **`flow/auth-bypass-via-wrapper`** — a route handler is wrapped in
  `withAuth(...)` (or similar) from a project-local module whose
  implementation doesn't actually verify the session.
- **`flow/secret-to-response`** — a `process.env.X` value (or a
  hardcoded credential-shaped string) reaches a response body without
  redaction.

Phase 2 adds single-file table-stakes rules and additional flow rules.
See [`docs/rules/`](docs/rules/) for the full catalog.

## How Stryx works

```
TypeScript source
    ↓
Layer 1: oxc parser → arena AST (per file, parallel)
    ↓
Layer 2: project semantic index + AST rules + taint engine
    ↓
Layer 3 (optional): LLM escalation on flagged uncertain zones, cached
    ↓
Findings (JSON, SARIF, GitHub annotations, human text)
```

Most issues are caught instantly by deterministic Rust analysis (Layer 2).
Genuinely ambiguous zones — for example, a custom helper sitting between
a source and a sink whose intent the engine can't decide statically — are
escalated to a Layer 3 LLM with a focused, rule-specific prompt. Verdicts
are cached by content hash, so repeat scans of unchanged code are free.

Layer 3 is opt-in: bring your own LLM API key to enable it, or run
with `--no-llm` for fully local deterministic scans (the default).

[Architecture deep-dive →](ARCHITECTURE.md)

## Status

**v0.1.0 — first stable release.** Phase 1 closed: substrate stable,
6 flow rules + 1 generic rule in the registry, 8-repo OSS
validation arc (~28,800 TS files, 0 engine-level false positives).
APIs follow SemVer from this point. See
[ADR 0011](docs/decisions/0011-v01-to-v02-transition.md) for the
Phase 2 plan.

- ✅ Architecture, ADRs, rule specs
- ✅ Foundational crates `stryx_index` and `stryx_taint`
- ✅ v0.1 flow rules:
  - `flow/unvalidated-body-to-db` (cross-file)
  - `flow/auth-bypass-via-wrapper` (cross-file)
  - `flow/secret-to-response` (single-file)
  - `flow/ssrf-via-fetch` (single-file, experimental)
  - `flow/redirect-open` (single-file, experimental)
  - `flow/path-traversal` (single-file, experimental)
- ✅ CLI binary (`cargo install --path crates/stryx_cli`)
- ✅ Pre-built binaries on [GitHub Releases](https://github.com/hafizhpratama/stryx/releases)
- 🚧 GitHub Action
- 🚧 napi-rs npm distribution
- 🚧 Homebrew formula
- 📋 Cross-file slice 2 for the three experimental rules (Phase 2)
- 📋 Additional rules: prompt-injection, XSS, command-injection,
  SQL-injection (Phase 2)
- 📋 Hono / Express support via source/sink adapters (Phase 3)
- 📋 Type-aware analysis, custom taint configs (Phase 4)

## Documentation

- [Getting Started](docs/getting-started.md)
- [Architecture](ARCHITECTURE.md)
- [Rule library](docs/rules/)
- [FAQ](docs/faq.md)
- [Glossary](docs/glossary.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Contributing

Stryx grows by community-contributed AI failure patterns. If you've
seen an AI tool generate code that should have been flagged but
wasn't, [open a rule request](.github/ISSUE_TEMPLATE/new-rule-request.md)
with the real output. That's how the rule library compounds.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup and the
rule-authoring workflow.

## License

[Apache 2.0](LICENSE). Permissive, with no plans to change.

## Acknowledgments

Built on:

- [oxc](https://github.com/oxc-project/oxc) — the Rust JS/TS parser.
- The OWASP and CWE catalogs — pattern descriptions and references.

Stryx is not affiliated with any of the above.

[^stats]: 41% AI-generated code figure: daily.dev 2026 developer
    trends report. 45% AI-code vulnerability rate: ACM communications,
    April 2026 ("Security Implications of AI-Generated Code"). Refresh
    with primary URLs and newer surveys as they publish.
