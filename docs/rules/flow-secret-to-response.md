# `flow/secret-to-response`

> Catches values from secret-shaped sources (`process.env.X` where X
> looks like a secret, hardcoded credential strings) that flow into a
> response body without redaction.

## Metadata

| Field | Value |
|---|---|
| Rule ID | `flow/secret-to-response` |
| Status | experimental |
| Severity | critical |
| Frameworks | Next.js (App + Pages Router); Hono / Express / Fastify via Phase 2 source adapters |
| Default | enabled |
| Added in | v0.1.0 |

## What this rule catches

A value carrying the `Secret` taint label reaches a response-body
sink without passing through a redaction step. Sources include:

- `process.env.X` where `X` matches a secret-shaped name pattern
  (`/SECRET|KEY|TOKEN|PASSWORD|API|JWT|PRIVATE|CREDENTIAL/i`) and is
  not in the public-by-convention allow-list (`NEXT_PUBLIC_*`,
  `PUBLIC_*`, `NODE_ENV`, `NEXT_RUNTIME`, `APP_VERSION`)
- Hardcoded string literals matching common credential shapes
  (Stripe `sk_live_*`, OpenAI `sk-*`, JWT three-part dot-separated,
  high-entropy hex strings of credential length, etc.)

Sinks include `Response.json(...)`, `res.send(...)`, `res.json(...)`,
`c.json(...)` (Hono), `reply.send(...)` (Fastify), and equivalent
framework helpers.

The flow may be intra-file or cross-file. Cross-file shape: a config
helper in `lib/config.ts` exports a `getConfig()` that includes
secrets, and `app/api/debug/route.ts` returns `Response.json(getConfig())`.

The consequence: secrets exposed at a public HTTP endpoint. This is
how production credentials end up in screenshots, error logs,
caching layers, and search engines.

## Why this happens

Debug, health, version, and admin endpoints often want to show
configuration. The unsafe shortcut is returning the full `process.env`
object or a `getConfig()` helper that bundles every env var
indiscriminately.

The same shape appears with health checks, debug panels, and admin
dashboards. These endpoints may be useful, but credentials should never
be response data.

## Bad example

```ts
// File: app/api/debug/config/route.ts
// Repro: debug endpoint returns secret-shaped environment values.

export async function GET() {
  return Response.json({
    env: process.env.NODE_ENV,
    apiKey: process.env.API_KEY,
    dbUrl: process.env.DATABASE_URL,
    stripeKey: process.env.STRIPE_SECRET_KEY,
    nextAuthSecret: process.env.NEXTAUTH_SECRET,
  });
}
```

Problems:

- Four of the five fields carry the `Secret` label.
- All four reach `Response.json(...)` directly with no redaction.
- A single GET to `/api/debug/config` exposes every credential in the
  deployment.
- This pattern is common enough that public scanners regularly find
  it on production deployments.

## Good example

```ts
// File: app/api/debug/config/route.ts

export async function GET() {
  return Response.json({
    env: process.env.NODE_ENV,
    appVersion: process.env.APP_VERSION,
    region: process.env.NEXT_PUBLIC_REGION,
    // Secrets deliberately omitted — debug endpoints should never
    // include credentials, even in development.
  });
}
```

Or, if the endpoint genuinely needs to confirm a secret is *set*
without revealing its value:

```ts
import { redact } from "@/lib/redact";

export async function GET() {
  return Response.json({
    env: process.env.NODE_ENV,
    apiKeyPresent: Boolean(process.env.API_KEY),
    stripeKeyFingerprint: redact(process.env.STRIPE_SECRET_KEY ?? ""),
  });
}
```

The taint engine recognizes `redact()` as a sanitizer (configured via
`stryx.toml`), and `Boolean(...)` produces a derived value that no
longer carries the `Secret` label.

## How to fix

Do not return secrets in HTTP responses, debug endpoints, health checks,
or error payloads. Return only non-sensitive metadata such as whether a
secret is configured, a redacted fingerprint, or a server-owned public
configuration value.

Keep debug endpoints behind auth, but do not treat auth as sufficient
for returning credentials. Secrets should remain non-response data even
for authenticated users.

## What Stryx recognizes

Recognized as safe:

- Omitting the secret from the response object.
- `Boolean(secret)` or `.length` style derived presence checks.
- Redaction helpers configured in `stryx.toml`.
- Explicit allow-listing for environment variables that are public by
  design.

Not recognized as safe:

- Returning `process.env.SECRET_*` directly.
- Spreading an object that contains secret-shaped fields into a response.
- Renaming a secret field to a harmless-looking key.
- Returning secrets only in development mode without a recognized guard.

## Taint signature

| Field | Value |
|---|---|
| Source labels | `Secret` |
| Source matchers | `process.env.X` where X matches the secret-name regex and is not allow-listed; hardcoded strings matching credential-shape regexes |
| Sink ids | `response.body` (Response.json, res.send, res.json, reply.send, c.json, ctx.body =, return new Response) |
| Sanitizers recognized | Allow-listed redaction helpers, `Boolean(...)` coercion (produces non-secret derived value), `.length` access (derived non-secret), explicit allow-list checks for env vars marked safe |
| Scope | `CrossFile` |

The default secret-name pattern is conservative; users can tighten or
loosen it via `stryx.toml`.

## Detection logic

1. The taint engine scans for `Secret` sources during the per-file
   index extract pass:
   - `process.env.X` where `X` matches the configured secret regex
     and isn't in the public allow-list.
   - String literal expressions whose value matches a known
     credential shape.
2. Forward propagation traces the labeled value through assignments,
   destructuring, object-literal construction, function calls, and
   await unwrap.
3. When the value reaches a `response.body` sink, the engine checks
   whether any sanitizer cleansed the `Secret` label along the path.
4. Object-property pruning is taint-aware: if `const { apiKey, ...safe } = config`
   and `Response.json(safe)` is the sink, the rule does not fire on
   `safe` (the `apiKey` was excluded).
5. If the value reaches the sink unsanitized: emit a Finding at the
   sink span; include the source location in the message.
6. If the engine bails (dynamic spread `...config`, computed property
   access, deep nesting beyond the recursion limit): emit an
   UncertainZone for LLM escalation.

## Known false positive zones

- **Public env vars conventionally prefixed** but using a name that
  matches the secret regex (e.g., `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY`
  is intentionally public despite containing `KEY`). The default
  allow-list covers `NEXT_PUBLIC_*`, `PUBLIC_*`, and common
  framework-public prefixes; extend via `stryx.toml`.
- **Server-rendered debug pages in development only** that
  conditionally return secrets when `NODE_ENV !== "production"`.
  The engine flags them; if your team policy permits this, suppress
  with a reason.
- **Health checks that intentionally return signed data**.
  Cryptographic signatures aren't secret material in the threat model;
  configure a custom sanitizer.
- **Webhook signing secrets used in HMAC computation** that flow to a
  response only as part of a derived hash. The hash output is not the
  secret; configure HMAC helpers as sanitizers.

If a false positive zone is common (>10% of expected fires), the
secret-name regex or the public allow-list needs tightening before
the rule goes beta.

## LLM escalation prompt (Layer 3)

```
You are analyzing a TypeScript code region for secret-leakage taint flow.

Source code:
{ZONE_SOURCE}

A static analyzer detected that a secret-shaped value (label: Secret,
originating at: {SOURCE_LOCATION}) flows toward a response-body sink,
but tracing cannot continue due to dynamic property access, spread
into an opaque object, or a similar bail condition.

Question: Does the secret value end up in the response body sent to
the client, without an effective redaction step?

Definitions:
- "Effective redaction" replaces the secret with a non-recoverable
  placeholder (e.g., a fingerprint, "***", a boolean presence check,
  or an HMAC over the secret).
- Object-key omission via destructuring or explicit allow-listing
  counts as redaction (the secret is dropped, not transformed).
- Returning the raw secret with a different field name is not
  redaction.

Return JSON only, no prose:
{
  "leaks_secret": boolean,
  "secret_label_origin": string,
  "redacted_by": string | null,
  "confidence": number,
  "reasoning": string
}
```

Confidence threshold for surfacing as a Finding: 0.7.

## Performance characteristics

- Source detection: ~0.2ms per file (regex match on env reads + string literals)
- Cross-file flow trace: ~3ms p99 per source-sink pair
- LLM escalation: ~1.0s per zone (cold), <5ms cached
- Most repos: 0–5 escalations per scan, dominated by debug endpoints

## Configuration

```toml
[rules."flow/secret-to-response"]
severity = "critical"   # default

# Override the default secret-name regex
secret_name_pattern = "(?i)SECRET|KEY|TOKEN|PASSWORD|API|JWT|PRIVATE|CREDENTIAL"

# Env vars to treat as public regardless of name
public_env_vars = [
  "NEXT_PUBLIC_*",
  "PUBLIC_*",
  "NODE_ENV",
  "NEXT_RUNTIME",
  "APP_VERSION",
  "MY_PUBLIC_API_BASE",
]

# Names recognized as redaction sanitizers
redactors = ["redact", "mask", "@/lib/redact.fingerprint"]

# Exempt files (e.g., test fixtures that intentionally contain secrets)
exempt_paths = ["tests/**", "examples/**"]
```

## Suppressing this rule

Inline:

```ts
// stryx-disable-next-line flow/secret-to-response -- dev-only endpoint, gated by NODE_ENV
```

File:

```ts
// stryx-disable flow/secret-to-response -- HMAC signing endpoint, secret participates in signature only
```

Project-wide disable is strongly discouraged given the severity. File
a false-positive issue if the rule fires inappropriately.

## See also

- [OWASP A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP A05:2021 — Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- Related rules:
  - `flow/unvalidated-body-to-db` — companion check for input flows
  - `sources/process-env-secret` — primitive source this rule consumes
  - `sources/hardcoded-credential` — primitive source this rule consumes
  - `sinks/response-body` — primitive sink this rule consumes

## History

| Version | Change |
|---|---|
| v0.1.0 | Initial implementation; experimental status. Pure-AST detection for the common case; LLM escalation only on dynamic-spread or computed-access ambiguity. |
