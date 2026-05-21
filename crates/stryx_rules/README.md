# `stryx_rules`

The rule catalogue and the [ADR 0008](../../docs/decisions/0008-taint-step-trait-substrate.md)
step substrate. Every detection lives here.

## Rule catalogue (v0.4.x)

14 rules in the registry. Cross-file rules use the iterative
two-pass extract→run pipeline with the convergence-signal tuple
from [ADR 0004](../../docs/decisions/0004-two-pass-fixpoint-with-iteration-cap.md).
Single-file rules are visitor-only.

| Rule ID | Scope | Severity | Doc |
|---|---|---|---|
| `generic/hardcoded-secret` | Single-file | Critical / High | [`docs/rules/generic-hardcoded-secret.md`](../../docs/rules/generic-hardcoded-secret.md) |
| `flow/unvalidated-body-to-db` | Cross-file | High / Medium | [`docs/rules/flow-unvalidated-body-to-db.md`](../../docs/rules/flow-unvalidated-body-to-db.md) |
| `flow/auth-bypass-via-wrapper` | Cross-file | High | [`docs/rules/flow-auth-bypass-via-wrapper.md`](../../docs/rules/flow-auth-bypass-via-wrapper.md) |
| `flow/secret-to-response` | Cross-file | High | [`docs/rules/flow-secret-to-response.md`](../../docs/rules/flow-secret-to-response.md) |
| `flow/ssrf-via-fetch` | Cross-file | High / Medium | [`docs/rules/flow-ssrf-via-fetch.md`](../../docs/rules/flow-ssrf-via-fetch.md) |
| `flow/redirect-open` | Cross-file | High | [`docs/rules/flow-redirect-open.md`](../../docs/rules/flow-redirect-open.md) |
| `flow/sql-injection` | Cross-file | Critical | [`docs/rules/flow-sql-injection.md`](../../docs/rules/flow-sql-injection.md) |
| `flow/command-injection-via-exec` | Cross-file | Critical | [`docs/rules/flow-command-injection-via-exec.md`](../../docs/rules/flow-command-injection-via-exec.md) |
| `flow/path-traversal` | Single-file | High | [`docs/rules/flow-path-traversal.md`](../../docs/rules/flow-path-traversal.md) |
| `flow/prompt-injection` | Single-file | High | [`docs/rules/flow-prompt-injection.md`](../../docs/rules/flow-prompt-injection.md) |
| `flow/xss-via-dangerously-set-inner-html` | Single-file | High | [`docs/rules/flow-xss-via-dangerously-set-inner-html.md`](../../docs/rules/flow-xss-via-dangerously-set-inner-html.md) |
| `flow/eval-injection` | Single-file | Critical | [`docs/rules/flow-eval-injection.md`](../../docs/rules/flow-eval-injection.md) |
| `flow/nosql-injection` | Single-file | High | [`docs/rules/flow-nosql-injection.md`](../../docs/rules/flow-nosql-injection.md) |
| `flow/insecure-deserialize` | Single-file | Critical | [`docs/rules/flow-insecure-deserialize.md`](../../docs/rules/flow-insecure-deserialize.md) |

Cross-file flow for the three v0.4.0 trio (eval / nosql /
deserialize) is planned for a future release; see the
[stack-aware roadmap](../../docs/roadmap/stack-aware-scanning.md).

## Step substrate

ADR 0008 closed the closed-enum `StepKind` registry. Each rule wires
its source/sink/sanitiser detectors as step variants and consults
them via `registry_as_source` / `registry_as_call_source` /
`registry_as_member_source` / `registry_as_sink` /
`registry_as_sanitizer` helpers.

[ADR 0014](../../docs/decisions/0014-adapter-substrate-api.md)
extends this with the `AstMatcher` closed-enum substrate that lets
22 stack adapters contribute framework-specific patterns
(sources, sinks, sanitisers, guards, propagators, decorated params)
without rules importing adapter code directly.

Module layout:

- `src/steps/sources/` — request-body / `req.query` / `req.params` /
  `req.files` source recogniser; Next.js App Router `searchParams.X`.
- `src/steps/sinks/` — db / response / fetch / redirect / fs / sql /
  exec / eval / nosql / deserialize / llm.
- `src/steps/sanitizers/` — parser (zod/valibot/yup/ajv/joi/
  class-validator), auth-check, redactor, URL allow-list.
- `src/steps/propagators/` — structural propagator (closed set
  of taint-propagating expression shapes).
- `src/steps/hof.rs` — ADR 0007 slice 3.6 placeholders
  (`FunCallable`, `FunPropagation`).
- `src/adapters_*.rs` — 22 stack adapters (one file per
  framework / runtime / data layer / validator / auth / LLM SDK).

## Adding a new rule

Follow the doc-first flow in [AGENTS.md](../../AGENTS.md#adding-or-changing-rules):
doc → fixtures → implementation → tests → registry → CHANGELOG.

Rule docs are remediation contracts. Each rule page must include
`How to fix` and `What Stryx recognizes` so CLI `Read more` links lead
to a concrete safe pattern, not vague best-practice advice.

## Stability

Rule IDs and `RuleMeta` are public contracts under SemVer. New
rules in minor versions; rule removals require a major bump.
