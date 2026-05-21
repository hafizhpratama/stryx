# Stack-Aware CLI Experience

This document defines the target CLI experience for Stryx once project
profiles and stack adapters land. The goal: a single command that
detects the user's TypeScript backend stack, runs the right security
checks against it, and reports findings with concrete fix hints — in a
form that's terse enough to act on in CI and dense enough to trust
locally. Product category is **TypeScript backend/platform security**;
React component quality, accessibility, and bundle advice are out of
scope.

## Product promise

Stryx detects the user's TypeScript server stack, enables the right
security adapters, then reports production-risk findings in the terms
that match the project.

The CLI should answer four questions quickly:

1. What stack did Stryx detect?
2. Which adapters did that detection enable?
3. What real risks did Stryx find?
4. What should the user change first?

## Non-goals

- No React hook, component architecture, rendering, accessibility, or
  bundle-style diagnostics.
- No generic style linting that ESLint, Biome, oxlint, TypeScript, or
  framework linters already cover well.
- No "best practice" warning unless it maps to a concrete security,
  dataflow, auth, secret, network, filesystem, command, or LLM-safety
  risk.

Next.js support is allowed only for backend surfaces: route handlers,
server actions, middleware, API routes, server-side auth, database calls,
and deployment runtime boundaries.

## Default command

```bash
npx @hafizhpratama/stryx@latest scan
```

Target behavior:

- If the scan root has one obvious project, run immediately.
- If the scan root is a workspace, prompt for projects unless
  `--all`, `--project`, or CI mode is present.
- If there are many uncommitted files, ask whether to scan only changed
  files in interactive mode. Never prompt in CI.
- In CI, default to deterministic output, no prompts, and stable exit
  codes.

## Example output

```text
stryx v0.5.0

✔ Select projects to scan › api
✔ Found 38 uncommitted changed files. Only scan those? … no
Scanning ./api...

✔ Detecting language. Found TypeScript.
✔ Detecting runtime. Found Bun.
✔ Detecting framework. Found Hono.
✔ Detecting database. Found Drizzle + PostgreSQL.
✔ Detecting validation. Found Zod.
✔ Detecting auth. Found Better Auth.
✔ Detecting LLM SDK. Found OpenAI.
✔ Found 214 source files.

✔ Enabled adapters.
  Runtime       bun
  Framework     hono
  Database      drizzle, postgres
  Validation    zod
  Auth          better-auth
  LLM           openai

✔ Running security checks.

Critical 3 issues
  ✖ SQL injection ×2
    Untrusted request input reaches a raw SQL sink without
    parameterisation.
    Use parameter binding or Drizzle query builders instead of
    sql.raw/user-built SQL.
    src/routes/search.ts:41

  ✖ Command injection
    Request input reaches Bun.spawn() as the executable or command
    argument.
    Keep the binary path static and pass user input only as fixed-position
    args.
    src/jobs/media.ts:88

High 9 issues
  ⚠ Unvalidated body to DB ×4
    Request JSON reaches a database write without a recognized validator
    on the path.
    Validate with zod/valibot/arktype before passing data into the
    persistence layer.
    src/routes/users.ts:29

  ⚠ SSRF via fetch ×2
    Request input reaches fetch() as a URL without an allow-list guard.
    Parse with URL and restrict host/protocol before making the outbound
    request.
    src/routes/proxy.ts:52
    Read more: https://stryx.dev/rules/flow-ssrf-via-fetch

  ⚠ Auth bypass via wrapper ×2
    Handler is wrapped in an auth-named helper, but the wrapper body does
    not verify a session.
    Ensure the wrapper calls Better Auth session validation and blocks
    unauthenticated requests.
    src/lib/with-auth.ts:14

  ⚠ Prompt injection
    User-controlled request text reaches an OpenAI prompt without
    instruction/data separation.
    Put user input in a delimited data field, not directly into system or
    developer instructions.
    src/routes/ai.ts:67

Medium 6 issues
  ⚠ Hardcoded secret ×3
    Credential-shaped string literal found in source.
    Move the value into a secret manager or environment variable.
    src/config/dev.ts:12

  ⚠ Open redirect ×2
    Request input reaches redirect() without an allow-list check.
    Restrict redirects to relative paths or approved hosts.
    src/routes/login.ts:103

  ⚠ Path traversal
    Request input reaches Bun.file() as a path.
    Resolve against a base directory and verify the resolved path remains
    inside it.
    src/routes/download.ts:31

  ⚠ 11 more warnings
    Run `npx @hafizhpratama/stryx scan . --verbose` to get all details

  ┌─────┐  82 / 100 Production ready
  │ >_< │  ███████████████████████████████████████████░░░░░░
  │  !  │  Stryx
  └─────┘

  18 issues across 12/214 files in 1.9s
  Full diagnostics written to /tmp/stryx-report-8a31.json

  → Add to CI:
    npx @hafizhpratama/stryx scan . --fail-on high
```

## Reporting model

The default human report should group findings by severity first:

- Critical
- High
- Medium
- Low
- Info

Within each severity group, findings should be grouped by rule, sorted by
impact and count. The default report prints up to three representative
locations per rule. `--verbose` prints every finding.

Each rule group should include:

- a one-line risk statement
- one concise fix hint
- one representative location
- a `Read more` link to the rule's fix guide

Do not label these links as "best practices." Use "Read more" or "Fix
guide" because Stryx reports concrete unsafe flows, not subjective style
preferences.

The JSON report must include the project profile so downstream tools can
explain why a rule or adapter was active:

```json
{
  "profile": {
    "language": "typescript",
    "runtimes": [{ "id": "bun", "confidence": 0.95 }],
    "frameworks": [{ "id": "hono", "confidence": 0.92 }],
    "data_layers": [{ "id": "drizzle", "confidence": 0.9 }],
    "validators": [{ "id": "zod", "confidence": 0.88 }],
    "auth_layers": [{ "id": "better-auth", "confidence": 0.81 }],
    "llm_sdks": [{ "id": "openai", "confidence": 0.76 }]
  },
  "adapters": ["runtime/bun", "framework/hono", "data/drizzle"],
  "findings": []
}
```

## Detection copy

Use precise status lines:

- `Found Bun.`
- `Found Hono.`
- `Found Drizzle + PostgreSQL.`
- `Not found.`
- `Inferred from imports.`
- `Possible, not enabled by default.`

Avoid vague copy like "recommendations enabled." Stryx enables adapters,
not taste.

## Score

The score should not ship until findings are stable enough to avoid
trust loss. When it ships, the score should be secondary to findings and
must not hide critical issues behind a high aggregate number.

Proposed bands:

| Score | Label | Meaning |
|---|---|---|
| 90-100 | Hardened | No high or critical findings; only low-risk backlog |
| 75-89 | Production ready | Some issues, but no critical blockers |
| 50-74 | Needs work | High-risk findings need attention |
| 0-49 | Blocked | Critical findings or broad unsafe flows |

Critical findings cap the score at 49. High findings cap the score at
74. This prevents a large safe codebase from hiding one serious bug.

## Exit codes

| Exit code | Meaning |
|---|---|
| 0 | Scan completed and no finding met `--fail-on` |
| 1 | Scan completed and at least one finding met `--fail-on` |
| 2 | CLI/config/runtime error |

`--fail-on` accepts `none`, `info`, `low`, `medium`, `high`, and
`critical`. CI defaults to `high`. Local interactive scans default to
`high` unless config overrides it.

## UX acceptance criteria

- A first-time user can see the detected stack before findings.
- A CI user can get deterministic output with no prompts.
- A user can understand why Bun/Hono/Drizzle-specific findings appeared.
- React/component quality never appears in the report.
- The default output is short enough to act on, with `--verbose` for full
  detail.
