# `flow/unvalidated-body-to-db`

> Catches request bodies that flow to a database write without runtime
> validation along the path — even when the flow crosses files.

## Metadata

| Field | Value |
|---|---|
| Rule ID | `flow/unvalidated-body-to-db` |
| Status | experimental |
| Severity | high |
| Frameworks | Next.js (App + Pages Router), Hono ≥ 4 (Phase 2), Express (Phase 2) |
| Default | enabled |
| Added in | v0.1.0 |

## What this rule catches

An HTTP request body (from `req.json()`, `req.formData()`, `req.text()`,
or framework-specific equivalents) flows into a database write
operation (Prisma, Drizzle, raw SQL via tagged template, MongoDB,
etc.) without passing through a runtime validator (zod, valibot, yup,
ajv, joi, or a custom sanitizer the user has allow-listed).

The flow may cross files. The most common shape is a route handler in
`app/api/.../route.ts` that calls a helper exported from `lib/...` —
the helper does the DB write, the handler does the parsing, and
neither validates. Single-file linters cannot see this; the project
semantic index plus the taint engine can.

The consequence: a malicious or malformed payload can cause type
confusion, unintended database writes, downstream injection, or simply
crash with a cryptic error instead of a clean 400. TypeScript types do
not validate runtime data — `as User` is a syntactic assertion, not a
runtime check.

## Why this happens

Teams commonly factor the database call into a helper without also
factoring in the validation boundary. The handler reads the request body,
the helper writes to the database, and both sides assume the other side
owns runtime validation.

The cross-file shape is what makes this hard to catch. Tutorial code
typically validates inline; production refactors move the persistence
call into a helper, and validation becomes nobody's responsibility.

## Bad example

Two files. The flow crosses both.

```ts
// File: app/api/users/route.ts
// Repro: route body flows into a helper that writes to the database.

import { createUser } from "@/lib/users";

export async function POST(req: Request) {
  const body = await req.json();
  const user = await createUser(body);
  return Response.json(user);
}
```

```ts
// File: lib/users.ts

import { db } from "@/lib/db";

export async function createUser(input: any) {
  return db.user.create({ data: input });
}
```

Problems:

- `req.json()` produces an unvalidated `any`-shaped object
- It crosses the file boundary unchanged via `createUser(body)`
- `db.user.create({ data: input })` writes whatever shape arrived
- A request setting `role: "admin"` reaches the database directly
- A request missing `email` produces a cryptic Prisma error, not a 400
- Extra fields silently end up in the database insert

## Good example

```ts
// File: app/api/users/route.ts

import { z } from "zod";
import { createUser } from "@/lib/users";

const createUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(100),
});

export async function POST(req: Request) {
  const result = createUserSchema.safeParse(await req.json());
  if (!result.success) {
    return Response.json(
      { error: "Invalid request", details: result.error.flatten() },
      { status: 400 }
    );
  }
  // Note: role is NOT a request field — authorization, not input
  const user = await createUser(result.data);
  return Response.json(user);
}
```

```ts
// File: lib/users.ts

import { db } from "@/lib/db";
import type { z } from "zod";
import type { createUserSchema } from "./schemas";

export async function createUser(input: z.infer<typeof createUserSchema>) {
  return db.user.create({ data: input });
}
```

The taint engine sees `createUserSchema.safeParse` as a sanitizer for
the `UntrustedInput` label and stops tracing. No finding emitted.

## How to fix

Validate request data at the trust boundary before passing it into
helpers, services, repositories, or ORM calls. The safest shape is:
parse the request body, validate it with a runtime schema, return a 400
when validation fails, and pass only the validated data onward.

Do not rely on TypeScript types, `as` assertions, generated DTO types, or
ORM model types for runtime safety. They describe what the code expects;
they do not check what the request actually sent.

## What Stryx recognizes

Recognized as safe:

- `zod.parse` / `safeParse` with failure handling.
- `valibot.parse` / `safeParse` with failure handling.
- `ajv.validate`, `joi.validateAsync`, and `yup.validate` when the
  validated value is the one passed onward.
- Cross-file validation wrappers that validate before calling the
  handler or database helper.
- User-configured validators in `stryx.toml` once configured.

Not recognized as safe:

- `const body = await req.json() as User`.
- Passing unvalidated `body` to a helper that later writes to the DB.
- Defining a schema without applying it to the request value.
- Validating one field while writing the rest of the original body.

## Taint signature

| Field | Value |
|---|---|
| Source labels | `UntrustedInput` |
| Sink ids | `db.write` (covers Prisma `*.create/.update/.upsert/.delete`, Drizzle insert/update/delete, raw SQL via tagged template, `mongoose.create`) |
| Sanitizers recognized | `zod.parse` / `safeParse`, `valibot.parse` / `safeParse`, `ajv.validate`, `joi.validateAsync`, `yup.validate`, plus user-allow-listed validators in `stryx.toml` |
| Scope | `CrossFile` |

## Detection logic

1. The taint engine identifies sources that produce `UntrustedInput`:
   `req.json()`, `req.formData()`, `req.text()`, `req.body` (Pages
   Router), framework-specific request body access points.
2. Forward propagation traces the labeled value through assignments,
   destructuring, await unwrap, and function calls — using cached
   function summaries from `stryx_taint` to cross file boundaries.
3. When the value reaches a `db.write` sink, the engine checks whether
   any sanitizer cleansed the `UntrustedInput` label along the path.
4. If sanitized: the flow is safe; no finding.
5. If unsanitized: emit a Finding at the sink span; include the
   cross-file path in the message ("flow crosses N files").
6. If the engine bails (dynamic dispatch, recursion past depth 3,
   opaque external function, eval-shape): emit an UncertainZone for
   LLM escalation rather than guessing.

The rule subscribes to taint flows matching its signature; it does not
walk the AST itself. See
[`taint-engine.md`](../architecture/taint-engine.md).

### Class-method resolution (NestJS shape)

When a controller method delegates to an injected service via
`this.<member>.<method>(arg)`, the rule resolves `<member>` against the
enclosing class's constructor parameter properties (`private readonly
userService: UsersService`) and class field declarations
(`private userService: UsersService`). The declared type name is
followed through the import map to a class declaration in either the
same file or another file, and the matching method's parameter summary
is consulted at the call site. Same-class `this.<method>(arg)` calls
also resolve. Field aliasing (`const u = this.userService`) and
dynamic dispatch (`this[name].create`) are not currently followed.

## Known false positive zones

- **Webhook handlers** that intentionally accept raw payloads (Stripe,
  GitHub) and verify a signature instead of validating shape.
  - Suppress: `// stryx-disable-next-line flow/unvalidated-body-to-db -- signed webhook payload`
  - Or in `stryx.toml`: declare under `exempt_paths`.
- **Routes behind authenticated middleware** that has already validated
  the body upstream. If the middleware is project-local, the engine
  sees the validation. If it lives in `node_modules`, treat the
  middleware export as a sanitizer in `stryx.toml`.
- **Custom validators** not in the default allow-list. Add them under
  `[taint.sanitizers]` or in this rule's `allow_validators`.
- **ORM raw query helpers** that internally validate. Configure as
  trusted sinks or as sanitizers depending on shape.

If a false positive zone is common (>10% of expected fires), the rule
needs to be tightened before going beta.

## LLM escalation prompt (Layer 3)

When the taint engine bails, the UncertainZone is sent to the LLM with
the prompt template at `crates/stryx_llm/prompts/flow/unvalidated-body-to-db.txt`:

```
You are analyzing a TypeScript code region for taint flow safety.

Source code:
{ZONE_SOURCE}

A static analyzer detected that an untrusted request body (label:
UntrustedInput) flows into a code region where static tracing cannot
continue. The analyzer suspects the value may reach a database write
sink: {CANDIDATE_SINKS}.

Question: Considering the dynamic dispatch and any sanitizers visible
in the region, does the untrusted value reach a database write without
an effective sanitizer?

Definitions:
- "Effective sanitizer" means a runtime check that constrains the
  value's shape and types (zod.parse, valibot.parse, ajv.validate,
  joi.validateAsync, yup.validate, or a custom validator with similar
  semantics).
- TypeScript type assertions (`as User`) are NOT sanitizers.

Return JSON only, no prose:
{
  "reaches_sink": boolean,
  "sink_id": string | null,
  "sanitized_by": string | null,
  "confidence": number,
  "reasoning": string
}
```

Confidence threshold for surfacing as a Finding: 0.7.

## Performance characteristics

- Function summary build: ~2ms per traced function (cold), <50µs (cached)
- Cross-file flow trace: ~5ms p99 per source-sink pair
- LLM escalation: ~1.1s per zone (cold), <5ms (cached)

In a typical Next.js repo with 50 API routes and a `lib/` layer, expect:
- ~30ms total taint analysis for this rule on the first scan
- ~5ms on subsequent scans (function-summary cache hits)
- 0–3 LLM escalations per scan, mostly cached on subsequent runs

## Configuration

```toml
[rules."flow/unvalidated-body-to-db"]
severity = "high"   # default

# Names recognized as runtime validators in addition to the defaults
allow_validators = ["myValidator", "@/lib/validate.body"]

# Glob patterns for files to ignore (typically webhook handlers)
exempt_paths = [
  "app/api/webhooks/**/route.ts",
  "app/api/stripe/webhook/route.ts",
]

# Treat specific sinks as already-validated by an internal layer
trusted_sinks = ["@/lib/db.queryUserScoped"]
```

## Suppressing this rule

Inline:

```ts
// stryx-disable-next-line flow/unvalidated-body-to-db -- webhook with signed payload
```

File:

```ts
// stryx-disable flow/unvalidated-body-to-db -- internal route validated upstream by middleware
```

Project-wide (not recommended; please file a false-positive issue first):

```toml
[rules]
disabled = ["flow/unvalidated-body-to-db"]
```

The `-- reason` is required. Suppression density is tracked across
scans for audit; see also `flow/suppression-density-meta` (Phase 2).

## See also

- [OWASP A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [zod documentation](https://zod.dev), [valibot](https://valibot.dev),
  [ajv](https://ajv.js.org), [joi](https://joi.dev),
  [yup](https://github.com/jquense/yup)
- Related rules:
  - `flow/auth-bypass-via-wrapper` — companion check for auth wrappers
  - `flow/secret-to-response` — companion check for secret leakage
  - `sanitizers/zod-parse` — primitive sanitizer this rule consumes
  - `sources/http-request-body` — primitive source this rule consumes
  - `sinks/db-write` — primitive sink this rule consumes

## History

| Version | Change |
|---|---|
| v0.1.0 | Initial implementation; experimental status. Replaces the planned single-file `nextjs/missing-zod-validation` with a cross-file flow rule per [ADR 0003](../decisions/0003-cross-file-and-taint-as-core.md). |
