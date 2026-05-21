# Glossary

> Each term means exactly one thing in this codebase. If you find these used
> otherwise — in code, docs, or commits — please fix it.

## Core concepts

### Pattern
A class of bug we want to catch. Conceptual, not yet implemented. Example:
*"Next.js API routes that consume request body without input validation."*
A Pattern is a category; a Rule is its concrete implementation.

### Rule
The Rust implementation of a Pattern, plus its accompanying documentation
and test fixtures. Each Rule has a stable `rule_id` (e.g.,
`flow/unvalidated-body-to-db`) that never changes once shipped. Rules
live under `crates/stryx_rules/src/{sources,sinks,sanitizers,flows}/<rule_id>.rs`
per [ADR 0003](decisions/0003-cross-file-and-taint-as-core.md).

### Finding
A concrete instance of a Rule firing on real code. A Finding includes:
- `rule_id` — which Rule produced it
- `severity` — info | low | medium | high | critical
- `span` — file path + start byte + end byte (or line/column)
- `message` — human-readable description
- `fix_hint` — optional remediation suggestion
- `confidence` — only present for findings derived via LLM escalation

A scan output is a list of Findings.

### Fix hint
A short remediation string attached to a Finding. The CLI prints it
inline; the rule page expands it into a full fix guide. Fix hints should
describe a concrete safe shape, not generic "best practice" advice.

### Fix guide
The remediation section in a rule doc. It explains how to change the
code and what Stryx recognizes as fixed. Fix guides live in
`docs/rules/*.md` under the `How to fix` and `What Stryx recognizes`
headings.

### Zone
A region of source code identified by file path + start byte + end byte.
Used as the unit of analysis for Layer 3 LLM escalation. Smaller than a
file, larger than a single AST node — typically a function body or
class definition.

### UncertainZone
A Zone that a Layer 2 (AST) Rule has flagged as potentially problematic
but cannot confirm without semantic context. UncertainZones are the input
to Layer 3 LLM escalation. They include the Zone plus the Rule that
flagged it and a brief reason.

If LLM escalation is disabled (`--no-llm`), UncertainZones are reported
separately as "inconclusive" and do not count as Findings.

### Escalation
The process of sending an UncertainZone to a Layer 3 LLM, getting a
verdict, and converting that verdict (if confident) into a Finding.
Escalations are cached by
`blake3(zone_source + taint_summary + rule_id + prompt_hash + model_version)`,
so repeat scans of unchanged code in the same taint context cost
nothing after the first call.

## Taint analysis

Defined per [ADR 0003](decisions/0003-cross-file-and-taint-as-core.md)
and detailed in [`architecture/taint-engine.md`](architecture/taint-engine.md).

### Source
A code construct that produces untrusted or sensitive data (e.g.,
`req.json()` produces `UntrustedInput`, `process.env.X` produces
`Secret`). Sources are implemented as small Rust files under
`crates/stryx_rules/src/sources/`.

### Sink
A code construct that consumes data dangerously when that data carries
a relevant `TaintLabel` (e.g., `db.user.create`, `child_process.exec`).
Sinks live under `crates/stryx_rules/src/sinks/`.

### Sanitizer
A code construct that cleanses a `TaintLabel` from a value (e.g.,
`zod.parse`, `validator.escape`, an auth check). Sanitizers live under
`crates/stryx_rules/src/sanitizers/`.

### TaintLabel
A category of taint a value carries. The shipped labels are
`UserInput` (request body / query / params / files / `searchParams`),
`AuthSubject` (verified session subject), `Secret`
(`process.env.X` or credential-shaped string), `DbRow` (data read
from a DB query), and `Any` (used by sanitisers that clear every
label). Adding a label is an ADR-level change.

### TaintFlow
A path from a Source through zero or more intermediate functions to a
Sink, with the labels carried along the way and the sanitizers (if any)
that touched them. The taint engine emits one `TaintFlow` per traced
flow; flow rules turn them into Findings.

### FunctionSummary
A cached, content-keyed description of how a function transforms
taint on its parameters: which labels it sanitises, which sinks it
reaches, which labels it preserves on the return value. Stored at
`~/.cache/stryx/summaries/` and survives across scans on the same
machine. The concrete v0.2 shape is `ExportedFunctionSummary`.

### ExportedFunctionSummary
The concrete shipped implementation of FunctionSummary. Produced by
each rule's `extract` pass; carries one `ParamFlow` per formal
parameter, plus `contains_auth_check` and `validates_request_body`
flags read by `flow/auth-bypass-via-wrapper` and
`flow/unvalidated-body-to-db`. Lives in
[`crates/stryx_taint/src/lib.rs`](../crates/stryx_taint/src/lib.rs).

### ParamFlow
The per-parameter slot inside an `ExportedFunctionSummary`. Carries
the five reach flags (`reaches_db_sink_unsanitized`,
`reaches_fetch_sink_unsanitized`, `reaches_redirect_sink_unsanitized`,
`reaches_sql_sink_unsanitized`, `reaches_exec_sink_unsanitized`) plus
the SSRF precision flag `fetch_sink_path_pinned_only` and the
shape-lattice fields (`tainted_offsets`, `param_shape`,
`return_shape`, `propagates_to_return`) from
[ADRs 0006 / 0007](decisions/0006-shape-lattice-taint-summary.md).
All reach flags are `#[serde(default)]` for cache-format compat.

### StepKind
The closed-enum substrate ([ADR 0008](decisions/0008-taint-step-trait-substrate.md))
that carries each rule's source / sink / sanitiser / propagator
recognisers. Every rule's taint logic dispatches through `StepKind`
via the six `TaintStep` trait methods (`as_source`, `as_call_source`,
`as_member_source`, `as_sink`, `as_sanitizer`, `as_propagator`).
v0.4.0 added the complementary closed-enum `AstMatcher` substrate
([ADR 0014](decisions/0014-adapter-substrate-api.md)) so 22 stack
adapters can contribute framework-specific patterns without rules
importing adapter code directly.

### ProjectIndex
The project-level read-only data structure built once per scan
(`stryx_index`). Holds symbols, imports, call sites, and framework
hints — enough to answer cross-file questions without keeping every
AST resident. See [`architecture/semantic-index.md`](architecture/semantic-index.md).

### ProjectProfile
The stack-detection model from
[ADR 0013](decisions/0013-stack-aware-project-profiles.md), shipped
in v0.3.0. It records detected language, runtime, framework, data
layer, validation, auth, LLM SDK, and deployment evidence so Stryx
can enable the right adapters. Built by the cheap-pass detector in
`stryx_index::profile` from `package.json`, lockfiles, and a small
set of config files — no source parsing required. As of v0.4.0 the
profile drives the registered [StackAdapter](#stackadapter) set,
and as of v0.4.1 it walks `workspaces` arrays so monorepo roots
aggregate per-workspace evidence.

### StackAdapter
A registered adapter that contributes stack-specific sources, sinks,
sanitisers, guards, and propagators to the generic rules via the
closed-enum `AstMatcher` substrate from
[ADR 0014](decisions/0014-adapter-substrate-api.md). Example:
`framework/hono` teaches Stryx about `c.req.json()` and `c.redirect()`;
`runtime/bun` teaches Stryx about `Bun.serve`, `Bun.spawn`, and
`Bun.write`. v0.4.0 ships 22 adapters (runtimes node/bun, frameworks
express/fastify/hono/nestjs/next, data layers prisma/drizzle/pg/mysql2,
validators zod/valibot/joi/yup/ajv/class-validator, auth
better-auth/auth-js/clerk, LLM SDKs openai/anthropic); P2 follow-ups
(mongoose, kysely, knex, elysia, lucia, supabase-auth, vercel-ai-sdk,
langchain) land on demand — see the
[stack-aware roadmap](roadmap/stack-aware-scanning.md).

### RuleScope
Either `SingleFile` or `CrossFile`. Declared by each rule so the
orchestrator knows whether to dispatch the rule per-file or per-project.

## Severity

We use 5 levels:

| Level | When to use |
|---|---|
| **info** | Notable but not a problem (e.g., "debug endpoint exposes too much context") |
| **low** | Minor concern, no immediate risk (e.g., missing JSDoc on auth function) |
| **medium** | Real issue but not exploitable directly (e.g., overly permissive logging) |
| **high** | Likely bug or security issue (e.g., missing input validation on API route) |
| **critical** | Severe, exploitable, or actively dangerous (e.g., hardcoded production secret) |

Default `fail_on` threshold is `high`. CLI exits non-zero when any Finding
at or above this threshold is emitted.

## Confidence

Only meaningful for Findings derived via Layer 3 LLM escalation. Range 0.0–1.0.

| Range | Default behavior |
|---|---|
| 0.0–0.5 | Discarded (not surfaced) |
| 0.5–0.7 | Surfaced as info-level only |
| 0.7–0.9 | Surfaced at the Rule's configured severity |
| 0.9–1.0 | Surfaced at the Rule's configured severity, marked "high confidence" |

Layer 2 (AST) Findings have no confidence — they're deterministic.

## Layers

### Layer 1 — Parser
The oxc-based parser. Takes TypeScript source, produces an arena-allocated
AST. We don't write code in Layer 1 — we use oxc's.

### Layer 2 — AST Rules
Deterministic Rust rules walking the AST. Run on every file in parallel.
Emit Findings (definite) and UncertainZones (maybe). Performance budget:
≤ 10ms per file at p99.

### Layer 3 — LLM Escalation
Optional semantic analysis of UncertainZones via a Large Language Model.
Cached aggressively. Disabled in deterministic mode (`--no-llm`).

When this doc says "Layer 1/2/3" without prefix, it always refers to these.

## Rule lifecycle

### Status: experimental
Newly added. May have false positives. May still be enabled by default
when the consequence is serious and the rule is conservative. The rule
doc must clearly describe known false-positive zones.

### Status: beta
Tested, low false positive rate. Enabled by default at non-critical
severity. We'd love feedback.

### Status: stable
Battle-tested across hundreds of repos. Suitable for CI gating.

### Status: deprecated
Being phased out. Still works, with a warning. Removed in next MAJOR.

## File and code conventions

### Fixture
A real-world TypeScript example used to test a Rule. Fixtures live in
`tests/fixtures/<rule-id>/`. Each rule has at minimum:
- `bad.ts` — code that should trigger the Rule
- `good.ts` — code that addresses the issue and should not trigger

### ADR (Architecture Decision Record)
A dated markdown document in `docs/decisions/` recording why we made a
significant architectural choice. Format: context, options considered,
decision, consequences. Once written, ADRs are append-only — superseded
by new ADRs, never edited.

### Hot path
Code that runs once per AST node or once per file in a typical scan.
Performance-sensitive. We prefer enum dispatch over `Box<dyn Trait>` here,
prefer `&str` over `String`, avoid allocations.

## Distribution and packaging

### napi-rs
The Rust ↔ Node.js bridge that lets us ship `npm install stryx`. It
compiles the Rust binary for each target platform and bundles them into
the npm package, so end users get a native binary without a Rust toolchain.

### Workspace
A Cargo concept: a collection of related crates with a single
`Cargo.toml` at the root. Stryx is a workspace; each `crates/<name>/`
is a member crate.

### Scan
One invocation of `stryx scan` against a TypeScript project. A scan
produces a list of Findings, an exit code reflecting the configured
severity threshold, and timing metadata.

## Things people might confuse

- A **Pattern** is what we want to catch (concept).
  A **Rule** is how we catch it (code).
  A **Finding** is what we caught (output).

- A **Zone** is a code region we point at.
  An **UncertainZone** is a Zone the AST flagged for LLM review.
  An **Escalation** is the LLM analyzing an UncertainZone.

- **Confidence** applies to Findings (0–1, only for LLM-derived).
  **Severity** applies to Rules and the Findings they produce
  (info/low/medium/high/critical).
