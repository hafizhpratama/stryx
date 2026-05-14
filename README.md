# Stryx

> Sees what your AI missed — across files.

A Rust static analyzer for AI-generated TypeScript. Stryx catches the
specific failure patterns AI coding tools commonly produce — missing
input validation, leaked secrets, weak auth, missing rate limits —
using cross-file taint analysis with optional LLM-confirmed intent on
genuinely ambiguous flows.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/hafizhpratama/stryx?label=release)](https://github.com/hafizhpratama/stryx/releases/latest)
[![CI](https://github.com/hafizhpratama/stryx/actions/workflows/ci.yml/badge.svg)](https://github.com/hafizhpratama/stryx/actions/workflows/ci.yml)

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

Pre-built binaries — attached to the [v0.2.1 GitHub Release](https://github.com/hafizhpratama/stryx/releases/tag/v0.2.1)
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

Ten rules in the registry today — three stable cross-file flows,
two cross-file flows promoted from experimental, four new
experimental flows for the AI-coding-tool audience and the
critical-severity injection classes, and one single-file generic.
See [`docs/rules/`](docs/rules/) for the full contracts.

**Stable (v0.1):**

- **`flow/unvalidated-body-to-db`** — request body flows to a database
  write without zod, valibot, ajv, joi, or yup along the path, even
  when the flow crosses files.
- **`flow/auth-bypass-via-wrapper`** — a route handler is wrapped in
  `withAuth(...)` (or similar) from a project-local module whose
  implementation doesn't actually verify the session.
- **`flow/secret-to-response`** — a `process.env.X` value (or a
  hardcoded credential-shaped string) reaches a response body without
  redaction.
- **`generic/hardcoded-secret`** — credential-shaped strings inline
  in source.

**Experimental (cross-file, v0.2):**

- **`flow/ssrf-via-fetch`** — body taint reaches `fetch` /
  `axios.<method>` / `got` as the URL, route → helper → sink
  chains included, URL-allow-list guards recognised.
- **`flow/redirect-open`** — same as SSRF but for redirect sinks
  (`NextResponse.redirect`, `next/navigation` `redirect`,
  `res.redirect`, `Response.redirect`).

**Experimental (single-file, v0.2):**

- **`flow/path-traversal`** — body taint reaches `fs.<method>` /
  `fsPromises.<method>` as the path argument.
- **`flow/prompt-injection`** — body taint reaches an LLM call's
  prompt content (`openai.chat.completions.create`,
  `openai.responses.create`, `anthropic.messages.create`).
- **`flow/xss-via-dangerously-set-inner-html`** — body taint reaches
  React's `dangerouslySetInnerHTML={{ __html: ... }}` JSX attribute
  without DOMPurify / sanitize-html wrapping.
- **`flow/sql-injection`** — body taint reaches a raw-SQL escape
  hatch (Prisma `$queryRawUnsafe` / `$executeRawUnsafe`, Drizzle
  `sql.raw`, node-postgres / mysql2 `<conn>.query`). Critical.
- **`flow/command-injection-via-exec`** — body taint reaches
  Node.js `child_process` `exec` / `execSync` / `execFile` /
  `execFileSync` / `spawn` / `spawnSync`. Critical.

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

**v0.2.1 — patch release.** All Critical-severity rules now have
cross-file taint coverage — `flow/sql-injection` and
`flow/command-injection-via-exec` joined SSRF, redirect-open, and
unvalidated-body-to-db in the cross-file tier. Plus one precision
fix on SSRF host-pinning (env-var-prefix templates now correctly
classified Medium path-injection). 10 rules in the registry, no
new rules vs. v0.2.0. APIs follow SemVer. See
[ADR 0011](docs/decisions/0011-v01-to-v02-transition.md) for
the Phase 2 plan and the v0.1 retrospective.

- ✅ Architecture, ADRs, rule specs
- ✅ Foundational crates `stryx_index` and `stryx_taint`
- ✅ Stable cross-file rules (v0.1):
  - `flow/unvalidated-body-to-db`
  - `flow/auth-bypass-via-wrapper`
  - `flow/secret-to-response`
- ✅ Experimental cross-file rules (v0.2 / v0.2.1):
  - `flow/ssrf-via-fetch` (slice 2 cross-file, three-level
    chain convergence, URL-allow-list sanitisers, env-host
    path-injection precision)
  - `flow/redirect-open` (slice 2 cross-file)
  - `flow/sql-injection` (slice 2 cross-file — Critical;
    Prisma `$queryRawUnsafe` / Drizzle `sql.raw` /
    node-postgres raw query)
  - `flow/command-injection-via-exec` (slice 2 cross-file —
    Critical; Node.js `child_process` exec / spawn / execFile)
- ✅ Experimental single-file rules (v0.2):
  - `flow/path-traversal`
  - `flow/prompt-injection` (OpenAI + Anthropic)
  - `flow/xss-via-dangerously-set-inner-html` (DOMPurify +
    sanitize-html sanitisers)
- ✅ App Router `searchParams.X` recognised as a body source
- ✅ CLI binary (`cargo install --path crates/stryx_cli`)
- ✅ Pre-built binaries on [GitHub Releases](https://github.com/hafizhpratama/stryx/releases)
- 🚧 GitHub Action
- 🚧 napi-rs npm distribution
- 🚧 Homebrew formula
- 📋 `flow/path-traversal` slice 2 (deferred — 0 OSS TPs in
  Phase 1 sample)
- 📋 ADR 0009 / ADR 0010 substrate pull-through (Phase 2
  Track C — guard-based barriers formalisation, external
  library summaries)
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
