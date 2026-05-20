# `flow/ssrf-via-fetch`

> Catches untrusted request input flowing to an outbound HTTP call as the URL.

## Metadata

| Field | Value |
|---|---|
| Rule ID | `flow/ssrf-via-fetch` |
| Status | experimental |
| Severity | high |
| Frameworks | nextjs >= 13, hono >= 4 (single-file + cross-file slice 2) |
| Default | enabled |
| Added in | v0.1.0 |

## What this rule catches

Server-Side Request Forgery (SSRF) happens when an application makes an
HTTP request to a URL the attacker controls. In cloud-deployed
Next.js apps the consequences include reading internal metadata
endpoints (e.g. `http://169.254.169.254/latest/meta-data/` on AWS),
calling internal-only services that trust network-position
authentication, exfiltrating credentials, or DoSing third parties
through the deployed app's IP.

Stryx flags when a value sourced from the request body or query
parameters reaches `fetch(...)`, `axios.<method>(...)`, or `got(...)`
as the URL argument without passing through a recognised allow-list
validator along the way.

## Why this happens

Backend features often need outbound HTTP: image proxies, URL preview
generators, OAuth callback intermediaries, webhook forwarders. The
unsafe shortcut is `const data = await fetch(req.body.url)`. It compiles
and works for happy-path URLs, but the attacker controls the destination
and can point it at internal services, cloud metadata endpoints, or
unexpected protocols depending on the runtime.

## Bad example

```ts
// Repro: request body controls the outbound fetch URL.

import type { NextRequest } from "next/server";

export async function POST(req: NextRequest) {
  const { url } = await req.json();
  const response = await fetch(url);
  const text = await response.text();
  return new Response(text);
}
```

## Good example

```ts
import type { NextRequest } from "next/server";

const ALLOW_HOSTS = new Set(["api.example.com", "cdn.example.com"]);

export async function POST(req: NextRequest) {
  const { url } = await req.json();
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return new Response("Invalid URL", { status: 400 });
  }
  if (!ALLOW_HOSTS.has(parsed.host)) {
    return new Response("Host not allowed", { status: 403 });
  }
  const response = await fetch(parsed.toString());
  const text = await response.text();
  return new Response(text);
}
```

## How to fix

Do not fetch arbitrary URLs supplied by the caller. Parse the value with
`new URL`, reject unsupported protocols, and allow only known hostnames
before making the outbound request. `new URL(input)` alone is not a
security control; it only proves the string is parseable.

For proxy-style endpoints, keep the public input as a logical identifier
or path segment whenever possible, then construct the upstream URL from a
server-owned base URL. If callers truly need to choose a host, restrict
the host with a constant allow-list and return a 4xx response before the
`fetch` when it does not match.

## What Stryx recognizes

Recognized as safe:

- `new URL(input)` followed by an allow-list check on `parsed.host` or
  `parsed.hostname` before `fetch`.
- A hardcoded URL or server-owned base URL where request input can only
  affect the path/query portion.
- Cross-file helpers that perform the allow-list check before the HTTP
  sink.

Not recognized as safe:

- `new URL(input)` without an allow-list.
- Checking that the string starts with `http`.
- Deny-listing `localhost` or `169.254.169.254` while allowing every
  other host.
- Fetching a request-provided URL and validating the response afterward.

## Taint signature

| Field | Value |
|---|---|
| Source labels | `UserInput` (body / query / headers) |
| Sink ids | `http.fetch`, `http.axios`, `http.got` |
| Sanitizers recognized | URL-allowlist check (`new URL(input)` + `if (!ALLOWED.has(parsed.host)) return`); `new URL(x)` alone is *not* a sanitizer |
| Scope | `SingleFile` + `CrossFile` |

## Detection logic

1. The visitor walks the program looking for HTTP-call sinks —
   bare `fetch(...)`, `axios.<method>(...)`, or `got(...)`.
2. For each sink call, the first argument (the URL) is examined
   for body-source taint via the existing `BodySource` step and
   the structural-propagator-walked taint set.
3. If the URL argument is tainted and no recognised allow-list
   sanitizer fired along the path, emit a Finding at the sink span.
4. **Cross-file (slice 2).** The extract pass simulates each
   exported function with one parameter pre-tainted and records
   `ParamFlow::reaches_fetch_sink_unsanitized` when the simulation
   observes a fetch sink. It also records
   `ParamFlow::fetch_sink_path_pinned_only` when *every* sink the
   parameter reaches uses a host-pinned URL template. The run pass
   walks call sites; when a tainted argument flows into a
   reach-flagged parameter slot of a callee resolved via the project
   index, a finding is emitted at the call site — High when any
   reachable sink is full-SSRF, Medium when every reachable sink is
   path-pinned.
5. **Host-pinned template recognition.** A template literal is
   considered host-pinned when:
   - the leading quasi pins a literal `https://example.com/...` or
     `http://example.com/...` prefix, OR
   - the leading quasi is empty, the first interpolation is
     operator-controlled (`process.env.X`, a `??` / `||` fallback
     chain whose left side is safe, or a binding previously
     initialised from one of those), and the second quasi starts
     with `/` to delimit the host portion.

## Known false positive zones

- **Internal allow-listed fetches** where the URL is validated via
  a host-check against a constant set, but Stryx doesn't yet
  recognise the validator shape
  → suppress with `// stryx-disable-next-line flow/ssrf-via-fetch -- allow-listed`
- **Proxy/forward endpoints** that intentionally forward arbitrary
  URLs (e.g. CDN signed-URL proxies that verify the signature
  separately)
  → suppress per-line; consider a dedicated allow-list for these
- **Test fixtures** with explicitly-untrusted localhost calls
  → suppress per-file with `// stryx-disable flow/ssrf-via-fetch`

If a false positive zone is common (>10% of fires), tighten the
rule before promoting from experimental.

## LLM escalation prompt (Layer 3)

Not applicable — slice 1 is fully deterministic at the AST layer.
A future slice may escalate "this looks like an allow-list but
Stryx can't prove it" zones.

## Performance characteristics

- AST analysis: ~0.3ms per file (single-file slice 1)
- Whole-pipeline impact: negligible — sink recognition adds one
  more closed-enum dispatch per call site.

## Configuration

```toml
[rules."flow/ssrf-via-fetch"]
severity = "high"
```

Future-slice options (post-v0.1.0):
```toml
allow_validators = ["myUrlChecker"]   # additional validators to recognise
extra_sinks = ["myHttpClient"]        # additional HTTP-call shapes
```

## Suppressing this rule

Inline:
```ts
// stryx-disable-next-line flow/ssrf-via-fetch -- reason
```

File-level:
```ts
// stryx-disable flow/ssrf-via-fetch
```

Project-level (`stryx.toml`):
```toml
[rules]
disabled = ["flow/ssrf-via-fetch"]
```

## See also

- OWASP A10:2021 — Server-Side Request Forgery
- CWE-918 — Server-Side Request Forgery
- AWS IMDSv2 metadata-endpoint hardening guidance
- Cloud-metadata exfiltration via SSRF: Capital One 2019 breach

## History

| Version | Change |
|---|---|
| v0.1.0 | Initial single-file slice — body source → `fetch`/`axios`/`got` sink. |
| v0.2 | Slice 2 — cross-file taint via `ExportedFunctionSummary::reaches_fetch_sink_unsanitized`. Route handler → imported helper → `fetch(...)` chains now fire at the call site. URL allow-list guard inside the helper suppresses the call-site finding. Three-level chain convergence (route → service → client). |
| v0.2.1 | Host-pinned-template precision: env-var-prefix templates (`fetch(\`${process.env.X}/...?id=${body.id}\`)`) downgrade from High (full SSRF) to Medium (path-injection), matching the literal-prefix shape. Recognition propagates through single-file and cross-file paths via the new `ParamFlow::fetch_sink_path_pinned_only` flag. Surfaced by the v0.1.0 papermark OSS sweep (`revalidateLinkById`). |
