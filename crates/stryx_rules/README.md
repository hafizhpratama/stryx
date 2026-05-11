# `stryx_rules`

The rule catalogue and the [ADR 0008](../../docs/decisions/0008-taint-step-trait-substrate.md)
step substrate. Every detection lives here.

## Rule catalogue (v0.1.0)

| Rule ID | Scope | Severity | Doc |
|---|---|---|---|
| `generic/hardcoded-secret` | Single-file | Critical | (built-in) |
| `flow/unvalidated-body-to-db` | Cross-file | High | [`docs/rules/flow-unvalidated-body-to-db.md`](../../docs/rules/flow-unvalidated-body-to-db.md) |
| `flow/auth-bypass-via-wrapper` | Cross-file | Critical | [`docs/rules/flow-auth-bypass-via-wrapper.md`](../../docs/rules/flow-auth-bypass-via-wrapper.md) |
| `flow/secret-to-response` | Single-file | Critical | [`docs/rules/flow-secret-to-response.md`](../../docs/rules/flow-secret-to-response.md) |
| `flow/ssrf-via-fetch` | Single-file | High / Medium | [`docs/rules/flow-ssrf-via-fetch.md`](../../docs/rules/flow-ssrf-via-fetch.md) |
| `flow/redirect-open` | Single-file | High | [`docs/rules/flow-redirect-open.md`](../../docs/rules/flow-redirect-open.md) |
| `flow/path-traversal` | Single-file | High | [`docs/rules/flow-path-traversal.md`](../../docs/rules/flow-path-traversal.md) |

## Step substrate

ADR 0008 closed the closed-enum `StepKind` registry: 14 variants
across four roles (source / sink / sanitiser / propagator). Each
new rule wires its source/sink/sanitiser detectors as step variants
and consults them via `registry_as_source` /
`registry_as_call_source` / `registry_as_member_source` /
`registry_as_sink` / `registry_as_sanitizer` helpers.

Module layout:

- `src/steps/sources/` — body source recogniser.
- `src/steps/sinks/` — db / response / fetch / redirect / fs.
- `src/steps/sanitizers/` — parser (zod/valibot/yup/conform),
  auth-check, redactor, URL allow-list.
- `src/steps/propagators/` — structural propagator (closed set
  of taint-propagating expression shapes).
- `src/steps/hof.rs` — ADR 0007 slice 3.6 placeholders
  (`FunCallable`, `FunPropagation`).

## Adding a new rule

Follow the doc-first flow in [CLAUDE.md](../../CLAUDE.md#adding-a-new-rule):
doc → fixtures → implementation → tests → registry → CHANGELOG.

## Stability

Rule IDs and `RuleMeta` are public contracts under SemVer. New
rules in minor versions; rule removals require a major bump.
