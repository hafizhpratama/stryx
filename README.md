<p align="center">
  <img src="docs/assets/logo.png" alt="Stryx logo" width="160" />
</p>

# Stryx

> Stack-aware security for JavaScript and TypeScript backends.

Stryx is a stack-aware security scanner for JavaScript and TypeScript
backends. It detects your runtime, framework, database, validation, auth,
and LLM SDK surface, then follows cross-file data flow to catch missing
input validation, leaked secrets, weak auth, unsafe redirects, SSRF, SQL
injection, command injection, path traversal, and unsafe LLM prompt
handling.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/hafizhpratama/stryx?label=release)](https://github.com/hafizhpratama/stryx/releases/latest)
[![CI](https://github.com/hafizhpratama/stryx/actions/workflows/ci.yml/badge.svg)](https://github.com/hafizhpratama/stryx/actions/workflows/ci.yml)

## Why

Modern JavaScript and TypeScript backends are assembled from many moving
parts: runtimes, routers, ORMs, validators, auth libraries, deployment
targets, and LLM SDKs. The risky part is rarely one line in isolation.
It is usually a flow across files: request data enters at a route,
passes through a helper, and reaches a database, shell, filesystem,
redirect, outbound fetch, response body, or LLM call without the right
safety boundary.

The hardest patterns to catch are flows that span multiple files — a
route handler in `app/api/.../route.ts` that passes `req.json()`
directly into a helper module's database write, with no validator
anywhere along the path. Single-file linters can't see the disconnect.
Reviewers may miss it. Tests rarely cover the malicious-payload case.

Stryx is built specifically for these cross-file backend flows. The
engine runs in milliseconds (Rust + oxc), produces deterministic findings
on the AST and project-index pass, and escalates only the small subset of
genuinely ambiguous zones to a cached LLM check.

## Install

From source — works today:

```bash
git clone https://github.com/hafizhpratama/stryx
cd stryx
cargo install --path crates/stryx_cli
```

Pre-built binaries — attached to the [v0.3.0 GitHub Release](https://github.com/hafizhpratama/stryx/releases/tag/v0.3.0)
across five targets (Linux x64/arm64, macOS x64/arm64, Windows x64).

npm — `npm install @hafizhpratama/stryx` or `npx @hafizhpratama/stryx
scan`. Cargo (`cargo install stryx-cli`) follows once the crate is
published to crates.io.

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

Rule pages are fix guides, not vague best-practice pages. Each rule doc
states what to change and what Stryx recognizes as fixed.

## What Stryx catches

Eleven rules in the registry today — three stable cross-file flows, four
additional cross-file security flows, three experimental single-file
flows, and one single-file generic.
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
JavaScript / TypeScript source
    ↓
Project profile: runtime / framework / data / auth / LLM evidence
    ↓
Layer 1: oxc parser → arena AST (per file, parallel)
    ↓
Layer 2: project semantic index + stack adapters + AST rules + taint engine
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

The next product direction is stack-aware scanning: Stryx detects the
TypeScript backend/platform stack (for example Bun + Hono + Drizzle +
Zod + Better Auth), enables the matching adapters, and keeps the rules
generic. See [ADR 0013](docs/decisions/0013-stack-aware-project-profiles.md)
and the [stack-aware roadmap](docs/roadmap/stack-aware-scanning.md).

## Status

**v0.4.0 — adapter substrate + DX shell + dogfood-closed rules.**
The `ProjectProfile` from v0.3.0 now drives 22 registered stack
adapters that contribute sources, sinks, sanitisers, guards, and
propagator patterns to the rules. The registry grows from 11 to 14
rules — three new categories (eval / NoSQL / deserialize) plus
broader sink/source coverage on the existing rules — surfaced by
dogfooding against OWASP NodeGoat, DVNA, Documenso, and the official
Prisma examples. The CLI gains a default scan subcommand, grouped
output with representative locations, a 0–100 Stryx Score with
severity caps, `--diff <base>` for PR-only CI runs, and per-rule
surface routing via `stryx.toml`. See [the CHANGELOG](CHANGELOG.md#040--2026-05-21)
for the full feature list.

- ✅ Architecture, ADRs, rule specs
- ✅ Foundational crates `stryx_index` and `stryx_taint`
- ✅ Cross-file rules:
  - `flow/unvalidated-body-to-db`
  - `flow/auth-bypass-via-wrapper`
  - `flow/secret-to-response`
  - `flow/ssrf-via-fetch` (needle/request/superagent/http(s) added
    in v0.4.0)
  - `flow/redirect-open`
  - `flow/sql-injection` (Critical; Prisma `$queryRawUnsafe` /
    Drizzle `sql.raw` / node-postgres raw query / Sequelize
    `db.sequelize.query` added in v0.4.0)
  - `flow/command-injection-via-exec` (Critical; Node.js
    `child_process` exec / spawn / execFile)
- ✅ Single-file rules:
  - `flow/path-traversal`
  - `flow/prompt-injection` (OpenAI + Anthropic)
  - `flow/xss-via-dangerously-set-inner-html` (DOMPurify +
    sanitize-html sanitisers)
  - `flow/eval-injection` — new in v0.4.0 (Critical; eval /
    Function / setTimeout-with-string)
  - `flow/nosql-injection` — new in v0.4.0 (High; MongoDB
    operator-injection shapes)
  - `flow/insecure-deserialize` — new in v0.4.0 (Critical;
    node-serialize, yaml.load unsafe, vm.runInX)
- ✅ Generic rule: `generic/hardcoded-secret` (provider-prefix
  Critical mode + credential-named-binding High mode as of v0.4.0)
- ✅ `ProjectProfile` cheap-pass detection (v0.3.0)
- ✅ 22 stack adapters wired into the rules (v0.4.0)
- ✅ Monorepo workspaces walked for per-template profile evidence
  (v0.4.0)
- ✅ Stryx Score (0–100, severity-capped), `[surfaces]` per-rule
  routing, `--diff <base>` PR-only mode (v0.4.0)
- ✅ App Router `searchParams.X` recognised as a body source
- ✅ CLI binary (`cargo install --path crates/stryx_cli`)
- ✅ Pre-built binaries on [GitHub Releases](https://github.com/hafizhpratama/stryx/releases)
- ✅ npm distribution (`@hafizhpratama/stryx`)
- 🚧 GitHub Action with sticky PR comment + annotations (v0.6.0)
- 📋 P2 adapter follow-ups (Elysia, mongoose, kysely, lucia,
  vercel-ai-sdk, etc.) as user demand surfaces
- 📋 Type-aware analysis, custom taint configs (later)

## Documentation

- [Getting Started](docs/getting-started.md)
- [Architecture](ARCHITECTURE.md)
- [Stack-aware CLI target](docs/product/stack-aware-cli.md)
- [Project profile architecture](docs/architecture/project-profile.md)
- [Stack adapter architecture](docs/architecture/stack-adapters.md)
- [Stack catalog](docs/stacks/)
- [Stack-aware roadmap](docs/roadmap/stack-aware-scanning.md)
- [Rule library](docs/rules/)
- [FAQ](docs/faq.md)
- [Glossary](docs/glossary.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Agent guide](AGENTS.md)

> **AI agents working in this repo** — Claude Code, Cursor, Copilot,
> Codex, and others — read [`AGENTS.md`](AGENTS.md). It is the single
> source of truth for agent context; [`CLAUDE.md`](CLAUDE.md) is only a
> compatibility redirect.

## Contributing

Stryx grows by community-contributed backend security patterns. If
you've seen a JavaScript or TypeScript backend flow that should have
been flagged but wasn't, [open a rule request](.github/ISSUE_TEMPLATE/new-rule-request.md)
with a minimal reproduction. That's how the rule library compounds.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup and the
rule-authoring workflow.

## License

[Apache 2.0](LICENSE). Permissive, with no plans to change.

## Acknowledgments

Built on:

- [oxc](https://github.com/oxc-project/oxc) — the Rust JS/TS parser.
- The OWASP and CWE catalogs — pattern descriptions and references.

Stryx is not affiliated with any of the above.
