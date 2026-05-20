# `flow/auth-bypass-via-wrapper`

> Catches route handlers wrapped in a project-local `withAuth`-shaped
> function whose implementation doesn't actually verify the session.

## Metadata

| Field | Value |
|---|---|
| Rule ID | `flow/auth-bypass-via-wrapper` |
| Status | experimental |
| Severity | critical |
| Frameworks | Next.js (App + Pages Router); Hono / Express via Phase 2 source adapters |
| Default | enabled |
| Added in | v0.1.0 |

## What this rule catches

A route handler is exported wrapped in a project-local function whose
name implies authentication or session enforcement (`withAuth`,
`requireAuth`, `requireSession`, `protected`, `authed`, etc.) — but
the wrapper's implementation doesn't actually call any auth check.
The handler looks protected from the call site; in reality, the
wrapper is a no-op or only adds incidental behavior.

The flow is cross-file by definition: the wrapper definition lives in
a separate module (typically `lib/auth.ts`) from the route handler
(`app/api/.../route.ts`). Single-file linters cannot see the
disconnect.

The consequence: an admin or otherwise sensitive endpoint is reachable
without authentication.

## Why this happens

Auth wrappers are easy to review incorrectly because the call site looks
protected: `withAuth(handler)`. The dangerous part is in another file,
where the wrapper may only preserve types, add logging, or leave a TODO
instead of checking a session before invoking the handler.

This is especially common when teams standardize wrapper names before
standardizing the auth mechanism. The wrapper shape exists, but the
enforcement branch does not.

## Bad example

```ts
// File: app/api/admin/users/route.ts

import { withAuth } from "@/lib/auth";
import { db } from "@/lib/db";

async function adminListUsers(_req: Request) {
  const users = await db.user.findMany();
  return Response.json(users);
}

export const GET = withAuth(adminListUsers);
```

```ts
// File: lib/auth.ts
// Repro: auth-named wrapper returns the handler without a session check.

type Handler = (req: Request) => Promise<Response>;

export function withAuth<H extends Handler>(handler: H): H {
  // TODO: add session check
  return handler;
}
```

Problems:

- The route name says "admin" — clearly intended to be authenticated.
- The wrapper signature looks like real auth scaffolding.
- The implementation is a no-op. Any unauthenticated request reaches
  `db.user.findMany()` and gets the full user list.
- The `TODO` is the kind of comment that ships unfinished.

## Good example

```ts
// File: lib/auth.ts

import { getServerSession } from "next-auth";
import { authOptions } from "./auth-options";

type Handler = (req: Request) => Promise<Response>;

export function withAuth<H extends Handler>(handler: H): Handler {
  return async (req: Request) => {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }
    return handler(req);
  };
}
```

The wrapper body calls a recognized auth check (`getServerSession`)
and short-circuits with a 401 on failure. The taint engine sees the
sanitizer call and clears the wrapper.

## How to fix

Make auth-named wrappers actually enforce authentication before they
call the inner handler. A valid wrapper must load or verify the session,
return or throw on failure, and only then invoke the protected handler.

If the route also needs authorization, check role, tenant, or permission
claims in the same pre-handler branch. A wrapper named `withAuth` that
only reads cookies, logs a session, or leaves a TODO is worse than no
wrapper because it gives reviewers false confidence.

## What Stryx recognizes

Recognized as safe:

- A recognized session/auth check before the wrapped handler is invoked.
- A failure branch that returns 401/403, redirects to login, or throws
  before execution reaches the inner handler.
- Cross-file wrappers where the project index resolves the wrapper body.
- Custom auth helper names configured in `stryx.toml`.

Not recognized as safe:

- A function named `withAuth` that returns the handler unchanged.
- Reading a session and ignoring the result.
- Checking auth after the handler already ran.
- Comments, TODOs, or TypeScript types claiming the route is protected.

## Taint signature

This rule uses a non-standard taint shape — it operates on the call
graph rather than data flow.

| Field | Value |
|---|---|
| Source | Call site that wraps a handler in a `withAuth`-shaped function. The wrapped handler becomes a "claimed-protected" object. |
| Sink | The inner handler being invoked inside the wrapper body. |
| Sanitizer | A recognized auth check call in the wrapper body before the inner handler is invoked. |
| Scope | `CrossFile` (the wrapper lives in a different module). |

Recognized auth checks (the default sanitizer set):

- `getServerSession` (NextAuth)
- `auth()` and `auth().protect()` (Clerk, NextAuth v5)
- `lucia.validateRequest()` / Lucia auth helpers
- `getSession()` from common adapters
- Custom names allow-listed via `stryx.toml`

Recognized wrapper name patterns (the default source set):

- Functions whose names match `/^with(Auth|Session|Login|User|Authentication)/i`
- Functions whose names match `/^(require|need|enforce)(Auth|Session|Login|User)/i`
- `protected`, `authed`, `secure`, `protect` (in handler-wrapping contexts)

Both sets are extensible via `stryx.toml`.

## Detection logic

1. The taint engine identifies wrapper call sites at the route's
   exported handler position: `export const POST = withAuth(handler)`
   or `export async function POST(req) { return withAuth(...)(req); }`.
2. The wrapper symbol is resolved via the project index. If it
   resolves to a project-local function, the engine fetches the
   wrapper's definition (re-parse on demand).
3. The wrapper body is walked looking for a recognized auth check
   call along *every* execution path that reaches the inner handler.
4. If every path is gated by an auth check: no finding.
5. If any path reaches the inner handler without an auth check: emit
   a Finding at the wrapper definition span; include the call site in
   the message.
6. If the wrapper resolves to a node-modules import, or its body
   uses dynamic dispatch / opaque helpers: emit an UncertainZone for
   LLM escalation.

The "every path" check is conservative: a wrapper with a
`session ?? returnNullSession()` shortcut is suspicious and gets
escalated to LLM rather than silently passed.

## Known false positive zones

- **Wrappers that delegate to a deeper auth helper** that the engine
  can't see (e.g., the wrapper imports from a private package). Allow-list
  the helper as a sanitizer in `stryx.toml`.
- **Public endpoints intentionally wrapped** in `withRateLimit` or
  similar non-auth wrappers whose name happens to match. Tighten the
  source pattern via `stryx.toml` or rename the wrapper to avoid
  triggering the heuristic.
- **Wrappers that authenticate by side effect** (e.g., setting a
  request-scoped context populated upstream). These genuinely need
  LLM review.
- **Multi-tier wrappers**: `withAuth(withRateLimit(handler))`. The
  engine traces through composition; the outer `withAuth` is the
  one we check.

## LLM escalation prompt (Layer 3)

When the wrapper's body is opaque to static analysis, the engine
emits an UncertainZone with this prompt:

```
You are analyzing a TypeScript wrapper function that, by name, claims
to enforce authentication on a route handler.

Wrapper definition:
{ZONE_SOURCE}

Question: Before the wrapper invokes the inner handler, does the
wrapper *actually* verify that the request is authenticated?

Definitions:
- "Verifying authentication" means a runtime check that calls a
  recognized auth helper (getServerSession, auth(), lucia.validateRequest,
  similar) and short-circuits the request with an error response when
  the check fails.
- A function that returns the inner handler unchanged is not auth.
- A function that calls an auth helper but ignores the result is not auth.
- TypeScript types alone do not enforce anything at runtime.

Return JSON only, no prose:
{
  "enforces_auth": boolean,
  "auth_helper_used": string | null,
  "short_circuits_on_failure": boolean,
  "confidence": number,
  "reasoning": string
}
```

Confidence threshold for surfacing as a Finding: 0.8 (higher than
most rules because false positives on this rule embarrass the user).

## Performance characteristics

- Wrapper body re-parse + walk: ~3ms per wrapper (cold), <100µs cached
- LLM escalation: ~1.2s per wrapper (cold), <5ms cached
- Most projects have ≤5 distinct wrappers; total overhead is small

## Configuration

```toml
[rules."flow/auth-bypass-via-wrapper"]
severity = "critical"   # default

# Additional names to recognize as auth-wrapper sources
wrapper_names = ["requireAdmin", "withOrgAuth"]

# Additional names to recognize as auth-check sanitizers
auth_helpers = ["@/lib/auth.requireSession", "myAuthClient.verify"]

# Wrappers to exempt (e.g., known non-auth wrappers whose name collides)
exempt_wrappers = ["withRateLimit", "withTracing"]
```

## Suppressing this rule

Inline at the wrapper definition:

```ts
// stryx-disable-next-line flow/auth-bypass-via-wrapper -- intentionally a no-op for testing
```

Inline at the call site (less preferred — the wrapper itself is the bug):

```ts
// stryx-disable-next-line flow/auth-bypass-via-wrapper -- public endpoint, name is misleading
```

Project-wide disable is strongly discouraged for this rule given its
critical severity. If you find yourself disabling it project-wide,
file a false-positive issue first.

## See also

- [OWASP A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
- [NextAuth.js documentation](https://next-auth.js.org/)
- Related rules:
  - `flow/unvalidated-body-to-db` — companion check for unvalidated input
  - `sources/route-handler-wrapped` — primitive source this rule consumes
  - `sanitizers/auth-check` — primitive sanitizer this rule consumes

## History

| Version | Change |
|---|---|
| v0.1.0 | Initial implementation; experimental status. Demonstrates the LLM-as-precision-recovery pattern (per [ADR 0003](../decisions/0003-cross-file-and-taint-as-core.md)) since wrappers' intent is hard to determine statically. |
