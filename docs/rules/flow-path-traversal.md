# `flow/path-traversal`

> Catches untrusted request input flowing to a filesystem call as the path argument.

## Metadata

| Field | Value |
|---|---|
| Rule ID | `flow/path-traversal` |
| Status | experimental |
| Severity | high |
| Frameworks | nextjs >= 13, hono >= 4 (single-file slice 1) |
| Default | enabled |
| Added in | v0.1.0 |

## What this rule catches

Path traversal happens when an application opens a filesystem path
the attacker controls. The classic exploit: the attacker passes
`../../etc/passwd` or `../../../.env` as a "filename" parameter
and reads server-side files that should never be exposed. On write
sinks (`writeFile`, `appendFile`) the consequence is overwriting
trusted files; on read sinks (`readFile`, `createReadStream`) it's
information disclosure.

Stryx flags when a value sourced from the request body or query
parameters reaches an `fs.<method>(path, ...)` call as the path
argument without a recognised path-resolve-then-prefix-check
sanitiser along the path.

## Why this happens

File-upload, file-download, and "serve user-uploaded image" handlers
often take a body-supplied filename and feed it straight to
`fs.readFile` or `fs.createReadStream`. The unsafe pattern is:

```ts
const { filename } = await req.json();
const data = await fs.promises.readFile(`./uploads/${filename}`);
```

The runtime threat model: the attacker can pass `../../etc/passwd`, and
`./uploads/../../etc/passwd` resolves outside the intended upload
directory.

## Bad example

```ts
// Repro: request-controlled filename reaches a filesystem read.

import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import fs from "fs/promises";

export async function GET(req: NextRequest) {
  const filename = req.nextUrl.searchParams.get("file");
  const data = await fs.readFile(`./uploads/${filename}`);
  return new NextResponse(data);
}
```

(Same pattern with `await req.json()` triggers the rule
identically.)

## Good example

```ts
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import fs from "fs/promises";
import path from "path";

const UPLOADS_ROOT = path.resolve("./uploads");

export async function POST(req: NextRequest) {
  const { filename } = await req.json();
  const resolved = path.resolve(UPLOADS_ROOT, filename);
  if (!resolved.startsWith(UPLOADS_ROOT + path.sep)) {
    return NextResponse.json({ error: "Invalid path" }, { status: 400 });
  }
  const data = await fs.readFile(resolved);
  return new NextResponse(data);
}
```

The canonical defense is `path.resolve(base, input)` followed by
`if (!resolved.startsWith(base + path.sep))`. Slice 1 does not yet
recognise this pattern as a sanitiser — that's a slice 2
candidate.

## How to fix

Never pass request-controlled path fragments directly to filesystem
APIs. Resolve the requested path against a server-owned base directory,
then verify the resolved path is still inside that base before reading,
writing, deleting, or streaming the file.

Prefer opaque IDs or database records over user-provided filenames when
possible. If filenames are part of the public API, also restrict allowed
characters and reject path separators unless the feature explicitly needs
subdirectories.

## What Stryx recognizes

Recognized as safe today:

- Hardcoded paths and server-owned base paths.

Planned for a future slice:

- `path.resolve(base, input)` followed by a prefix check before the
  filesystem sink.
- User-configured path guard helpers in `stryx.toml`.

Not recognized as safe:

- String concatenation like `"./uploads/" + filename`.
- Template paths like `` `./uploads/${filename}` ``.
- Replacing `"../"` with an empty string.
- Checking extensions while leaving directories attacker-controlled.

## Taint signature

| Field | Value |
|---|---|
| Source labels | `UserInput` (body / query / headers) |
| Sink ids | `fs.read.*`, `fs.write.*`, `fs.delete.*`, `fs.stat.*` (see step doc for the full method set) |
| Sanitizers recognized | None in slice 1. The fix guide documents the correct safe shape, but current recognition is still intentionally conservative. |
| Scope | `SingleFile` (slice 1); `CrossFile` (slice 2) |

## Detection logic

1. Walk the program looking for `fs.<method>(path, ...)` shapes
   across `fs.X`, `fsPromises.X`, and `fs.promises.X` receivers.
2. For each matching sink, the first argument (the path) is
   examined for body-source taint via the existing `BodySource`
   step and the structural-propagator-walked taint set.
3. If the path argument is tainted and no recognised sanitiser
   fired (slice 1 has none), emit a Finding at the sink span.

Slice 1 covers same-file flows. Slice 2 extends to cross-file via
the existing summary index.

## Known false positive zones

- **Hardcoded path with a body-supplied non-path field** — won't
  fire (the body value never reaches the path slot).
- **Trusted paths from a join with an allow-listed filename** —
  the file is sourced from a body field that's already validated
  against an allow-list. Stryx doesn't yet recognise the allow-list
  shape on path-string inputs.
  → suppress per-line with
    `// stryx-disable-next-line flow/path-traversal -- allow-listed`
- **Test fixtures that intentionally exercise traversal** —
  suppress per-file.

## LLM escalation prompt (Layer 3)

Not applicable — slice 1 is fully deterministic at the AST layer.

## Performance characteristics

- AST analysis: ~0.3ms per file (single-file slice 1).

## Configuration

```toml
[rules."flow/path-traversal"]
severity = "high"
```

## Suppressing this rule

```ts
// stryx-disable-next-line flow/path-traversal -- reason
```

## See also

- OWASP A01:2021 — Broken Access Control (covers path traversal).
- CWE-22 — Improper Limitation of a Pathname to a Restricted
  Directory ('Path Traversal').
- CWE-23 — Relative Path Traversal.
- Companion rules: [`flow/ssrf-via-fetch`](./flow-ssrf-via-fetch.md)
  and [`flow/redirect-open`](./flow-redirect-open.md) — sibling
  "body data reaches an unsafe sink" rules.

## History

| Version | Change |
|---|---|
| v0.1.0 | Initial single-file slice — body source → `fs.<method>` sink, no sanitiser. |
