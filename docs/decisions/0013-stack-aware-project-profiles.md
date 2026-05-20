# ADR 0013 — Add stack-aware project profiles

- **Date**: 2026-05-20
- **Status**: Proposed
- **Decider**: Hafizh Pratama
- **Refines**: [ADR 0003](0003-cross-file-and-taint-as-core.md),
  [ADR 0008](0008-taint-step-trait-substrate.md),
  [ADR 0011](0011-v01-to-v02-transition.md)

## Context

Stryx already catches cross-file TypeScript security flows, but the
current rule implementation has framework and platform knowledge mixed
directly into rules and step recognizers. That works for the first rule
set, but it will not scale cleanly to Bun, Hono, Express, Fastify,
NestJS, Drizzle, Better Auth, OpenAI, Cloudflare Workers, and other
backend/platform stacks.

The desired product experience is:

```text
Detect TypeScript stack
  → enable relevant adapters
  → run generic security flow rules
  → report findings in stack-specific vocabulary
```

Stryx's product boundary is TypeScript backend/platform security.
React component quality, hooks, rendering performance, accessibility,
and bundle advice are out of scope.

## Decision

Introduce a `ProjectProfile` and `StackAdapter` architecture.

`ProjectProfile` records detected stack dimensions:

- language
- runtime
- framework
- data layer
- validation library
- auth/session layer
- LLM SDK
- deployment target

Each detected hint stores confidence and evidence. Reporters surface the
profile so users can understand why Stryx enabled a Bun, Hono, Drizzle,
or Better Auth adapter.

`StackAdapter`s translate detected stacks into facts for the taint
engine:

- sources
- sinks
- sanitisers
- guards
- propagators when needed

Rules remain generic. For example, `flow/sql-injection` should not
become `flow/bun-sql-injection`, `flow/drizzle-sql-injection`, and
`flow/pg-sql-injection`. The rule owns the vulnerability semantics;
adapters own the stack-specific syntax.

## Consequences

Positive:

- New stack support can land without forking every rule.
- CLI output can explain the user's actual stack.
- Config can enable/disable adapters by stable adapter ID.
- JSON output can include profile evidence for CI and bug reports.
- Stryx's product boundary stays clear: backend/platform security.

Negative:

- More architecture before adding new stack coverage.
- Profile confidence thresholds need careful tuning.
- Mixed monorepos need project-level profiles, not only root-level
  detection.
- Current source/sink recognizers need migration into adapter-shaped
  modules.

## Implementation outline

1. Add `ProjectProfile` data types under `stryx_index` or a new
   `stryx_profile` crate if the module grows too large.
2. Add cheap evidence detection from package/config/lock files.
3. Add source evidence detection during the existing extract pass.
4. Include the profile in `ProjectIndex`.
5. Pass profile access through `RuleContext`.
6. Add `AdapterRegistry` in `stryx_rules`.
7. Migrate current generic recognizers behind adapter-style functions.
8. Broad adapter pass: ship adapters for all P0/P1 stacks in the
   catalog in one release — runtime/{node,bun},
   framework/{next-backend,hono,express,fastify,nestjs},
   data/{prisma,drizzle,pg,mysql2,mongoose},
   validation/{zod,valibot,yup,joi,ajv,class-validator},
   auth/{better-auth,auth-js,clerk}, llm/{openai,anthropic}.
   Each adapter ships shallow-but-correct: the 3-5 most common
   idioms per role, with remaining gaps documented per rule.
9. P2 adapters (deno, cloudflare-workers, elysia, oak, kysely, knex,
   bun-sqlite, bun-sql, arktype, typebox, supabase-auth, lucia,
   vercel-ai-sdk, langchain) ship as patch releases as real-world
   codebases surface needs.

## Adapter IDs

Adapter IDs are stable strings:

```text
runtime/bun
framework/hono
data/drizzle
validation/zod
auth/better-auth
llm/openai
```

These IDs can appear in:

- CLI profile output
- JSON reports
- `stryx.toml`
- suppressions or future policy packs
- GitHub Action comments

## Profile confidence

Adapters are enabled by default when profile confidence is at least
`0.60`. Reporter copy maps confidence like this:

| Confidence | Copy | Default adapter behavior |
|---|---|---|
| `>= 0.80` | Found | Enable |
| `0.60-0.79` | Inferred | Enable |
| `0.35-0.59` | Possible | Do not enable unless configured |
| `< 0.35` | Weak | Ignore |

Confidence is evidence-based and deterministic. No network calls,
package installs, or LLM calls are allowed during detection.

## Non-goals

- No React component analysis.
- No broad code-quality scoring in this ADR.
- No user-defined adapter language in the first implementation.
- No score until findings and profile detection are stable.
- No automatic dependency installation or external service calls.

## Open questions

- Whether `ProjectProfile` belongs inside `stryx_index` or in a new
  `stryx_profile` crate.
- Whether source evidence should be gathered by adapters directly or by
  a shared detector that adapters query.
- How much workspace/project selection should ship before the GitHub
  Action.
- Whether score should be tied to enabled adapters or only to emitted
  findings.
