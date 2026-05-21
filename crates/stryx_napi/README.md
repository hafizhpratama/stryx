# @hafizhpratama/stryx

> Stack-aware security for JavaScript and TypeScript backends.

A stack-aware security scanner for JavaScript and TypeScript backends.
Stryx detects runtime, framework, database, validation, auth, and LLM SDK
surfaces, then catches missing input validation, leaked secrets, weak
auth, SQL injection, command injection, SSRF, open redirects, path
traversal, and unsafe LLM prompt handling using **cross-file taint
analysis** that single-file linters can't match.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/hafizhpratama/stryx/blob/main/LICENSE)
[![npm](https://img.shields.io/npm/v/@hafizhpratama/stryx.svg)](https://www.npmjs.com/package/@hafizhpratama/stryx)

## Install

```bash
npm install -g @hafizhpratama/stryx
# or one-off
npx @hafizhpratama/stryx scan
```

The package ships prebuilt native binaries for macOS (x64 / arm64),
Linux (x64 / arm64-gnu), and Windows (x64-msvc). npm picks the right
platform binary at install time via `optionalDependencies` — total
download is ~1.5 MB per user.

## Quick start

```bash
cd your-typescript-project
npx @hafizhpratama/stryx scan
```

Output:

```
critical flow/sql-injection  app/api/search/route.ts:14:22
         Untrusted request input reaches a raw-SQL call as the query
         string without parameterisation (OWASP A03 / CWE-89).
         help: Switch to `prisma.$queryRaw`...`` (tagged template),
               which binds values instead of splicing.

1 finding(s): 1 critical, 0 high, 0 medium, 0 low, 0 info
```

Exit code is non-zero when any finding meets or exceeds the
`--fail-on` threshold (default: `high`). Drop it into CI to gate
deploys.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--format` | `human` | Output format: `human` or `json` |
| `--fail-on` | `high` | Minimum severity for non-zero exit: `info` / `low` / `medium` / `high` / `critical` |
| `--version` | — | Show version |
| `--help` | — | Show help |

```bash
npx @hafizhpratama/stryx scan ./src --format=json
npx @hafizhpratama/stryx scan . --fail-on=medium
```

## What it catches

14 rules in the registry. Highlights:

| Rule | Severity | Catches |
|---|---|---|
| `flow/sql-injection` | Critical | Body taint → `$queryRawUnsafe` / `sql.raw` / `db.sequelize.query` / raw query |
| `flow/command-injection-via-exec` | Critical | Body taint → `child_process` exec/spawn |
| `flow/eval-injection` | Critical | Body taint → `eval` / `Function` / `setTimeout`-with-string |
| `flow/insecure-deserialize` | Critical | Body taint → `node-serialize.unserialize` / `yaml.load` / `vm.runInX` |
| `flow/ssrf-via-fetch` | High/Medium | Body taint → `fetch` / `axios` / `got` / `needle` / `request` / `http(s).X` |
| `flow/nosql-injection` | High | Body-shaped object → MongoDB `collection.find/update/delete` |
| `flow/redirect-open` | High | Body taint → `NextResponse.redirect` etc. |
| `flow/unvalidated-body-to-db` | High | Body → Prisma/Drizzle/TypeORM/Mongoose/NestJS injected service without zod/valibot/yup |
| `flow/auth-bypass-via-wrapper` | High | `withAuth(...)` wrapper that doesn't actually check |
| `flow/secret-to-response` | High | `process.env.X` reaching response body |
| `flow/path-traversal` | High | Body taint → `fs.<method>` path |
| `flow/prompt-injection` | High | Body taint → LLM prompt content (OpenAI / Anthropic) |
| `flow/xss-via-dangerously-set-inner-html` | High | Body taint → React `dangerouslySetInnerHTML` |
| `generic/hardcoded-secret` | Critical/High | Provider-prefix tokens (AWS / Anthropic / Stripe / GitHub / OpenAI) + credential-named bindings with secret-shaped values |

**Eight rules trace flows across files** — a route handler in
`app/api/.../route.ts` that hands data to a helper in `lib/<x>.ts`
which then sinks to a DB / fetch / exec call is caught at the route's
call site, even though no single file shows the full path. The three
v0.4.0 rules (eval / NoSQL / deserialize) are single-file at v0.4.x
and gain cross-file flow in v0.5.0.

See the [full rule library](https://github.com/hafizhpratama/stryx/tree/main/docs/rules)
on GitHub.

Each rule page is also a fix guide: it explains the concrete safe pattern
and what Stryx recognizes as fixed.

## How it works

```
JavaScript / TypeScript source + package.json + lockfiles + configs
    ↓
Project profile: detect runtime / framework / data layer /
                 validator / auth / LLM SDK / deployment from
                 package metadata (no source parsing)
    ↓
Layer 1: oxc parser → arena AST (per file, parallel)
    ↓
Layer 2: project semantic index + 22 stack adapters + AST rules
         + taint engine (adapters consume the profile; rules consult
         the active adapter set during taint propagation)
    ↓
Layer 3 (optional): LLM escalation on flagged uncertain zones, cached
    ↓
Findings (JSON or human text), prepended by a compact stack block:
    stack: language: typescript • runtime: bun • framework: hono • ...
```

Most findings come from deterministic Rust analysis in milliseconds.
Genuinely ambiguous zones (a custom helper whose intent the engine
can't decide statically) escalate to an LLM check — bring your own
API key, or omit and stay fully local.

[Architecture deep-dive →](https://github.com/hafizhpratama/stryx/blob/main/ARCHITECTURE.md)

## Suppress false positives

Inline:

```ts
// stryx-disable-next-line flow/sql-injection -- signed webhook
```

File-level:

```ts
// stryx-disable flow/sql-injection
```

Found a false positive? [Open an issue](https://github.com/hafizhpratama/stryx/issues/new)
with the real code that triggered it.

## Performance

- ≤ 10 ms per 500-line TS file (p99)
- ≤ 30 s for a 10k-file repo with no LLM
- Sub-1 ms per rule per file

## Status

**v0.4.1** — adapter substrate + DX shell + dogfood-closed rules.
The `ProjectProfile` from v0.3.0 now drives 22 registered stack
adapters that contribute sources, sinks, sanitisers, guards, and
propagator patterns to the generic rules. The registry ships 14
rules — three new categories (`flow/eval-injection`,
`flow/nosql-injection`, `flow/insecure-deserialize`) alongside
broader sink/source coverage on the older rules. The CLI gains a
default-scan subcommand, grouped findings with representative
locations, a 0–100 Stryx Score with severity caps, `--diff <base>`
for PR-only CI runs, surface controls in `stryx.toml`, monorepo
workspace traversal, and a `STRYX_DEBUG_DUMP=1` diagnostic side
channel. APIs follow SemVer. See the
[changelog](https://github.com/hafizhpratama/stryx/blob/main/CHANGELOG.md)
for release-by-release detail and the
[roadmap](https://github.com/hafizhpratama/stryx/blob/main/docs/roadmap/stack-aware-scanning.md)
for what's next.

## Links

- **Repo**: [hafizhpratama/stryx](https://github.com/hafizhpratama/stryx)
- **Issues**: [github.com/hafizhpratama/stryx/issues](https://github.com/hafizhpratama/stryx/issues)
- **Rule library**: [docs/rules/](https://github.com/hafizhpratama/stryx/tree/main/docs/rules)
- **License**: Apache 2.0
