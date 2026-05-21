# Rule Library

Every rule Stryx ships, with status, severity, scope, and a one-line
description. See each rule's linked doc for the full contract (bad/
good examples, taint signature, detection logic, sanitisers
recognised, known FP zones, history).

## Status legend

- 🟢 **stable** — battle-tested on real OSS code, suitable for CI gating
- 🔵 **experimental** — newly shipped, may surface false positives; opt-in trust
- ⚪ **planned** — designed but not yet implemented

## Scope legend

- **single-file** — detection works within one file (no project index)
- **cross-file** — taint flows across imports via
  `ExportedFunctionSummary` from the project index

## Rule docs as fix guides

Every rule page is also a remediation guide. Stryx should not tell users
"follow best practices" and leave the fix vague. Each rule doc must state:

- what to change
- where the safety boundary belongs
- what Stryx recognizes as fixed
- what common "fixes" are still unsafe

This is especially important for stack-aware adapters: the CLI can stay
short (`Fix: parse with URL and allow-list host/protocol`), while the
rule page explains exact accepted shapes for Next.js, Hono, Express,
Bun, Drizzle, Better Auth, OpenAI, and future adapters.

## Rules shipped at v0.4.x

14 rules in the registry. Source under
`crates/stryx_rules/src/{generic,flows}/`.

### Stable cross-file flows (v0.1)

Per [ADR 0003](../decisions/0003-cross-file-and-taint-as-core.md),
these are the load-bearing rules — each demonstrates cross-file
taint analysis no single-file linter can match.

| Rule ID | Status | Severity | Scope | What it catches |
|---|---|---|---|---|
| [`flow/unvalidated-body-to-db`](flow-unvalidated-body-to-db.md) | 🔵 | high | cross-file | Request body flows to a DB write (Prisma / Drizzle / TypeORM / Mongoose / NestJS injected service) without zod / valibot / yup / ajv / joi anywhere along the path |
| [`flow/auth-bypass-via-wrapper`](flow-auth-bypass-via-wrapper.md) | 🔵 | high | cross-file | Handler wrapped in `withAuth(...)` from a project-local module whose body doesn't actually verify the session |
| [`flow/secret-to-response`](flow-secret-to-response.md) | 🔵 | high | cross-file | `process.env.X` or hardcoded credential-shaped string reaches a response body without redaction |

### Experimental cross-file flows (v0.2 – v0.4)

| Rule ID | Status | Severity | Scope | What it catches |
|---|---|---|---|---|
| [`flow/ssrf-via-fetch`](flow-ssrf-via-fetch.md) | 🔵 | high / medium | cross-file | Body / `req.query` / `req.params` taint reaches `fetch` / `axios.<m>` / `got` / `needle` / `request` / `superagent` / `http(s).{get,request}` as the URL; pinned-host templates downgrade to Medium path-injection |
| [`flow/redirect-open`](flow-redirect-open.md) | 🔵 | high | cross-file | Body / query / params taint reaches `NextResponse.redirect` / `next/navigation` `redirect` / `res.redirect` / `Response.redirect` |
| [`flow/sql-injection`](flow-sql-injection.md) | 🔵 | critical | cross-file | Body taint reaches a raw-SQL escape hatch (Prisma `$queryRawUnsafe`, Drizzle `sql.raw`, node-postgres / mysql2 / Sequelize `db.sequelize.query` / TypeORM `dataSource.query`) |
| [`flow/command-injection-via-exec`](flow-command-injection-via-exec.md) | 🔵 | critical | cross-file | Body taint reaches Node.js `child_process` `exec` / `execSync` / `execFile` / `spawn` / `spawnSync` |

### Experimental single-file flows (v0.2 – v0.4)

These do not (yet) traverse imports — cross-file flow for the
v0.4.0 trio (`flow/eval-injection`, `flow/nosql-injection`,
`flow/insecure-deserialize`) is on the
[stack-aware roadmap](../roadmap/stack-aware-scanning.md).

| Rule ID | Status | Severity | Scope | What it catches |
|---|---|---|---|---|
| [`flow/path-traversal`](flow-path-traversal.md) | 🔵 | high | single-file | Body / query / params taint reaches `fs.<method>` / `fsPromises.<method>` as the path argument |
| [`flow/prompt-injection`](flow-prompt-injection.md) | 🔵 | high | single-file | Body taint reaches OpenAI / Anthropic LLM-call prompt content (`messages[].content`, `input`) |
| [`flow/xss-via-dangerously-set-inner-html`](flow-xss-via-dangerously-set-inner-html.md) | 🔵 | high | single-file | Body taint reaches React's `dangerouslySetInnerHTML={{ __html: ... }}` without DOMPurify / sanitize-html |
| [`flow/eval-injection`](flow-eval-injection.md) | 🔵 | critical | single-file | Body / query / params taint reaches `eval` / `Function` / `new Function` / `setTimeout`-with-string / `setInterval`-with-string |
| [`flow/nosql-injection`](flow-nosql-injection.md) | 🔵 | high | single-file | Body-shaped object literal reaches a MongoDB collection `find` / `findOne` / `update` / `delete` / `aggregate` call (operator-injection via `{$gt:""}`, `{$where:...}`) |
| [`flow/insecure-deserialize`](flow-insecure-deserialize.md) | 🔵 | critical | single-file | Body / files / query taint reaches `node-serialize.unserialize` / `js-yaml` `yaml.load` (unsafe) / Node `vm.runInNewContext` / `runInThisContext` / `runInContext` |

### Generic single-file (v0.1, extended in v0.4)

| Rule ID | Status | Severity | Scope | What it catches |
|---|---|---|---|---|
| [`generic/hardcoded-secret`](generic-hardcoded-secret.md) | 🔵 | critical / high | single-file | Provider-prefix tokens (AWS `AKIA…`, Anthropic `sk-ant-…`, Stripe `sk_live_/test_…`, GitHub `ghp_…`, OpenAI `sk-…`) AND credential-named bindings (`apiKey`, `STRIPE_SECRET_KEY`) holding plausible-secret values |

## How rules are organized

Per [ADR 0003](../decisions/0003-cross-file-and-taint-as-core.md),
rules live under `crates/stryx_rules/src/{sources,sinks,sanitizers,flows}/`:

- **flows/** — cross-cutting taint rules. Most user-visible findings
  come from here.
- **sources/sinks/sanitizers/** — primitives the taint engine composes
  into flows. Adding a new framework usually means adding source/
  sink adaptations under these folders, not new flow rules.

Rule IDs follow `<category>/<kebab-case-name>`. Once published, a
rule ID is permanent — if we radically change a rule's semantics,
we ship under a new ID and deprecate the old one.

The `StepKind` substrate ([ADR 0008](../decisions/0008-taint-step-trait-substrate.md))
carries the per-rule step variants × 6 trait methods. Every rule's
taint logic dispatches through it. As of v0.4.0, rules also consult
the active set of 22 stack adapters via the closed-enum `AstMatcher`
substrate ([ADR 0014](../decisions/0014-adapter-substrate-api.md))
to pick up framework-specific sources, sinks, sanitisers, and guards.

## Adding a rule

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the full workflow.
Short version:

1. Find the failure in a real backend security pattern or minimal
   reproduction. Preserve the source, sink, guard, and stack shape.
2. Write the doc first following [`_template.md`](_template.md),
   including the "How to fix", "What Stryx recognizes", and
   "Taint signature" sections.
3. Implement under
   `crates/stryx_rules/src/{sources,sinks,sanitizers,flows}/<rule_id>.rs`.
4. Add `tests/fixtures/<rule-id>/{bad,good}.ts` (or
   `cross-file-{bad,good}/` directories for cross-file flows).
5. Add an integration test in `crates/stryx_cli/tests/rules.rs` and
   a criterion bench in `crates/stryx_rules/benches/`.
6. Register the rule in `crates/stryx_rules/src/registry.rs`.
7. Update `CHANGELOG.md`. Open a PR.

## Requesting a rule

Found a dangerous backend flow that we don't catch?
[Open a rule request](../../.github/ISSUE_TEMPLATE/new-rule-request.md)
with a minimal reproduction.

## Disabling rules

Per-finding, per-file, or per-project — see
[Getting Started](../getting-started.md#suppressing-false-positives).

If you find yourself disabling a rule project-wide, please report
it as a false-positive issue. We'd rather fix the rule than lose
a user.

## Severity philosophy

We're conservative with severity. A rule firing at `critical` should
mean *"this could cause a production incident in days, not weeks."*
If that calibration drifts, users will start ignoring all our
findings.

The Critical-severity rules in v0.4.x are the four code-execution
classes (`flow/sql-injection`, `flow/command-injection-via-exec`,
`flow/eval-injection`, `flow/insecure-deserialize`) — all RCE-class
with no mitigations from authentication alone. The provider-prefix
mode of `generic/hardcoded-secret` (AWS / Anthropic / Stripe /
GitHub keys) is also Critical because a leaked production credential
is an immediate incident. Everything else is High or below.

When in doubt, default to `medium` and let users escalate via
`stryx.toml` config.
