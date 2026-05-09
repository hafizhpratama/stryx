# Rule Library

Every rule Stryx ships, with status, severity, and a one-line description.

## Status legend

- 🟢 **stable** — battle-tested, suitable for CI gating
- 🟡 **beta** — works, low false positive rate, feedback welcome
- 🔵 **experimental** — newly added, may have false positives, opt-in via flag
- ⚪ **planned** — designed but not yet implemented

## v0.1 flow rules

Per [ADR 0003](../decisions/0003-cross-file-and-taint-as-core.md),
these are the rules v0.1 ships with — each demonstrates cross-file
taint analysis no single-file linter can match.

| Rule ID | Status | Severity | What it catches |
|---|---|---|---|
| [`flow/unvalidated-body-to-db`](flow-unvalidated-body-to-db.md) | 🔵 | high | Request body flows to DB write without zod/valibot/yup, even across files |
| [`flow/auth-bypass-via-wrapper`](flow-auth-bypass-via-wrapper.md) | 🔵 | critical | Handler wrapped in `withAuth(...)` from a project module that doesn't actually check auth |
| [`flow/secret-to-response`](flow-secret-to-response.md) | 🔵 | critical | `process.env.X` or hardcoded secret reaches a response body via any path |

## Phase 2 — single-file table-stakes

| Rule ID | Status | Severity | What it catches |
|---|---|---|---|
| `generic/hardcoded-secret` | ⚪ | critical | Detected API keys, JWT secrets, DB URIs in source |
| `generic/console-log-credential` | ⚪ | high | Logging objects that contain secrets |
| `generic/eval-or-function-string` | ⚪ | high | `eval()` or `new Function(string)` usage |
| `generic/sql-template-string` | ⚪ | critical | Raw SQL via template strings (injection risk) |
| `generic/regex-dos-pattern` | ⚪ | medium | Catastrophic backtracking patterns |
| `nextjs/weak-nextauth-config` | ⚪ | high | Default secrets, dev callbacks shipped to prod |
| `nextjs/cors-wildcard-on-auth` | ⚪ | high | `Allow-Origin: *` on routes touching auth |
| `nextjs/middleware-bypass-pattern` | ⚪ | critical | Middleware patterns vulnerable to known CVEs |

## Phase 2 — additional flow rules

| Rule ID | Status | Severity | What it catches |
|---|---|---|---|
| `flow/missing-rate-limit` | ⚪ | medium | Public API handler reaches no rate-limiter sanitizer along the call chain |
| `flow/server-action-no-auth` | ⚪ | high | Next.js Server Action invokes a sink without `getServerSession()` first |
| `flow/rsc-direct-db-no-scope` | ⚪ | medium | RSC component reaches DB sink without an RLS-scoped client |

## Hono and Express

Phase 3 — added via new sources/sinks, not rule rewrites. Existing flow
rules apply unchanged once the framework adapters land.

## How rules are organized

Per ADR 0003, rules live under
`crates/stryx_rules/src/{sources,sinks,sanitizers,flows}/`:

- **flows/** — cross-cutting taint rules. Most user-visible findings
  come from here.
- **sources/sinks/sanitizers/** — primitives the taint engine composes
  into flows. Adding a new framework usually means adding source/sink
  adaptations under these folders, not new flow rules.

Rule IDs follow the format `<category>/<kebab-case-name>`. Once
published, a rule ID is permanent. If we radically change a rule's
semantics, we ship it under a new ID and deprecate the old one.

## Adding a rule

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the full workflow. The
short version:

1. Find the failure in real AI output (don't invent examples)
2. Write the doc following [`_template.md`](_template.md) first,
   including the "Taint signature" section
3. Implement under
   `crates/stryx_rules/src/{sources,sinks,sanitizers,flows}/<rule_id>.rs`
4. Add `tests/fixtures/<rule-id>/{bad,good}/` (directories for cross-file flows)
5. Add an integration test and a criterion bench
6. Open a PR

## Requesting a rule

Found AI generating something dangerous that we don't catch?
[Open a rule request](../../.github/ISSUE_TEMPLATE/new-rule-request.md)
with the real output. We review weekly.

## Disabling rules

Per-finding, per-file, or per-project — see [Getting Started](../getting-started.md#suppressing-false-positives).

If you find yourself disabling a rule project-wide, please report it as a
false-positive issue. We'd rather fix the rule than lose a user.

## Rule severity philosophy

We're conservative with severity. A rule firing at `critical` should mean
*"this could cause a production incident in days, not weeks."* If that
calibration drifts, users will start ignoring all our findings.

When in doubt, default to `medium` and let users escalate via config.
