# Stack Adapter Architecture

Stack adapters are how Stryx becomes TypeScript backend/platform aware
without turning into a pile of framework-specific rules.

Rules stay generic:

- `flow/unvalidated-body-to-db`
- `flow/sql-injection`
- `flow/command-injection-via-exec`
- `flow/path-traversal`
- `flow/redirect-open`
- `flow/ssrf-via-fetch`
- `flow/secret-to-response`
- `flow/prompt-injection`

Adapters teach those rules how each stack expresses sources, sinks,
sanitisers, and guards.

## Concept

An adapter contributes facts to the taint engine:

| Adapter role | Examples |
|---|---|
| Source | `req.body`, `await req.json()`, `c.req.json()`, `params.slug` |
| Sink | `db.insert`, `sql.raw`, `Bun.spawn`, `res.redirect`, `Bun.write` |
| Sanitiser | `zod.parse`, `valibot.parse`, `ajv.validate`, URL allow-list check |
| Guard | `auth.api.getSession`, `getServerSession`, auth middleware |
| Propagator | helper functions, wrappers, object projections, response builders |

The rule asks whether a tainted source reaches a sensitive sink without
an accepted sanitiser/guard. It should not care whether that source came
from Hono, Express, Bun, Next.js, or another platform.

Adapters do not create vague "best practice" findings. They only add the
stack-specific facts needed for existing security rules to produce
concrete findings and fix hints.

## Adapter trait sketch

```rust
pub trait StackAdapter: Send + Sync {
    fn id(&self) -> AdapterId;
    fn kind(&self) -> AdapterKind;

    /// Whether this adapter should run for the detected project.
    fn is_enabled(&self, profile: &ProjectProfile) -> bool;

    /// Optional source-pass contribution. Used when source code gives
    /// stronger evidence than package metadata.
    fn extract<'a, 'b>(&self, ctx: &AdapterContext<'a, 'b>) -> AdapterExtract;

    fn sources(&self) -> &'static [SourcePattern];
    fn sinks(&self) -> &'static [SinkPattern];
    fn sanitisers(&self) -> &'static [SanitiserPattern];
    fn guards(&self) -> &'static [GuardPattern];
}

pub struct AdapterId(&'static str);

pub enum AdapterKind {
    Runtime,
    Framework,
    DataLayer,
    Validator,
    Auth,
    LlmSdk,
    Deployment,
}
```

Adapter IDs are public enough to appear in config and reports. Use
namespaced IDs:

- `runtime/bun`
- `framework/hono`
- `framework/express`
- `data/drizzle`
- `validation/zod`
- `auth/better-auth`
- `llm/openai`

## Pattern sketches

```rust
pub struct SourcePattern {
    pub id: &'static str,
    pub label: TaintLabel,
    pub matchers: &'static [AstMatcher],
}

pub struct SinkPattern {
    pub id: &'static str,
    pub sink: SinkKind,
    pub matchers: &'static [AstMatcher],
    pub severity_floor: Severity,
}

pub struct SanitiserPattern {
    pub id: &'static str,
    pub sanitizer: SanitizerKind,
    pub matchers: &'static [AstMatcher],
}

pub struct GuardPattern {
    pub id: &'static str,
    pub guard: GuardKind,
    pub matchers: &'static [AstMatcher],
}
```

The exact matcher representation can evolve. The important contract is
that adapters contribute typed facts, not free-form strings.

## Example adapters

### `framework/hono`

Sources:

- `await c.req.json()`
- `c.req.query()`
- `c.req.param("id")`
- route params passed into handlers

Sinks:

- `c.redirect(...)`
- `c.json(...)` for secret-to-response

Guards:

- middleware that calls a recognized auth/session checker and returns
  before `await next()` when unauthenticated

### `runtime/bun`

Sources:

- `Bun.serve({ fetch(req) { ... } })` request parameter
- `await req.json()` inside a Bun server handler
- `new URL(req.url).searchParams`

Sinks:

- `Bun.spawn(...)`
- `Bun.spawnSync(...)`
- `Bun.file(path)`
- `Bun.write(path, ...)`
- `Bun.sql` / `Bun.SQL`
- `import { $ } from "bun"` raw shell escape usage

Notes:

- Bun shell template interpolation escapes string variables by default.
  Do not flag ordinary `$` template interpolation as command injection.
  Flag raw interpolation, manually constructed command strings, and
  user-controlled executable/binary paths.

### `data/drizzle`

Sinks:

- `sql.raw(...)`
- raw SQL helpers
- unsafe template construction passed to query execution
- insert/update values for `flow/unvalidated-body-to-db`

Safe paths:

- query builder values after recognized validation
- parameterized placeholders

### `validation/zod`

Sanitisers:

- `schema.parse(value)`
- `schema.safeParse(value)` when success is checked before use
- `z.parse(value)` when `z` is a Zod namespace import

Non-sanitisers:

- schema declaration alone
- `safeParse` result used without checking `success`
- `as SomeType` TypeScript assertions

### `auth/better-auth`

Guards:

- session lookup followed by explicit unauthenticated return/throw
- middleware that blocks before reaching the handler

Non-guards:

- importing Better Auth without checking session
- calling a helper named `withAuth` whose body never validates a session
- reading a session and ignoring the result

## Rule interaction

A rule should see normalized facts:

```text
source: user_input.http_body
sink: db.write
sanitiser: validator.schema_parse
guard: auth.session_required
```

It should not have framework branches like:

```text
if hono { ... } else if express { ... } else if bun { ... }
```

Those branches belong in adapters. This keeps new stack support from
duplicating rule logic.

## Adapter enablement

Adapters are enabled when:

- the project profile detects the stack at confidence `>= 0.60`
- config explicitly enables the adapter
- a rule requires a generic adapter that is always safe to run

Adapters are disabled when:

- config disables them
- confidence is below threshold
- they conflict with a stronger project-level hint and no file-level
  evidence exists

Mixed projects are allowed. File-level evidence can enable an adapter for
one file even when the root profile is generic.

## Implementation sequence

1. Add `ProjectProfile`. (v0.3.0 — shipped)
2. Add `AdapterRegistry`. (v0.4.0)
3. Move existing hard-coded source/sink recognizers behind adapter-like
   functions without changing behavior. (v0.4.0)
4. Broad adapter pass: ship sources, sinks, sanitisers, and guards for
   every P0/P1 adapter in the stack catalog in one release. Each adapter
   ships shallow-but-correct — recognize the 3-5 most common idioms per
   role, document remaining gaps in the rule docs. No first-class stack,
   no second-class stack. (v0.4.0)
5. P2 adapters land as patch releases as users surface real codebases
   that need them.

## Testing contract

Each adapter must ship:

- detection fixture
- source fixture
- sink fixture
- sanitiser/guard fixture when applicable
- negative fixture for common false positives
- at least one cross-file fixture if it affects flow rules

Each rule must have at least one fixture proving that a new adapter
actually feeds the generic rule instead of bypassing the substrate.

## Performance budget

Adapters must preserve the existing Stryx budget:

- profile cheap pass: under 200 ms for a 10k-file repo excluding file IO
- adapter source extraction: under 1 ms per file per active adapter
- no LLM calls during profile detection
- no network calls during detection

Profile and adapter detection must be deterministic from the local
workspace contents.
