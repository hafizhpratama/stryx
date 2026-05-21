# `flow/insecure-deserialize`

> Catches untrusted request input flowing into a deserializer that
> evaluates its payload as code — `node-serialize`'s `unserialize`,
> `js-yaml`'s `yaml.load`, or Node's `vm.runInX` family.

## Metadata

| Field | Value |
|---|---|
| Rule ID | `flow/insecure-deserialize` |
| Status | experimental |
| Severity | critical |
| Frameworks | generic Node, express, nextjs >= 13 (single-file slice 1) |
| Default | enabled |
| Added in | v0.4.0 |

## What this rule catches

Insecure deserialization happens when an application hands an
attacker-supplied payload to a parser that evaluates parts of the
payload as code. The classic case is `node-serialize`'s
`unserialize`: the package recognises an `IIFE`-wrapped function
literal in the input and *runs it* at parse time. Equivalent
shapes exist in `js-yaml`'s unsafe `yaml.load` (which resolves the
`!!js/function` tag) and in Node's `vm` module
(`runInNewContext` / `runInThisContext` / `runInContext`), which
exists explicitly to evaluate strings as JavaScript.

The consequence in every case is arbitrary code execution under
the application's process identity — file-system access, network
egress, secret-store access, lateral movement. This is OWASP
A08:2021 (Software and Data Integrity Failures) and CWE-502
(Deserialization of Untrusted Data).

## Why this happens

These APIs are all "convenience" parsers. `node-serialize` is
chosen for round-tripping functions across processes; tutorials
show it being applied to request bodies because it "just works".
`js-yaml`'s `load` is the default examples on Stack Overflow even
though the documented safe variant (`safeLoad`) exists alongside
it. `vm.runInNewContext` is reached for whenever someone wants
to evaluate user-supplied "expressions" — a calculator endpoint,
a rule engine, a template language — and the cost of writing a
real parser feels prohibitive.

The shared failure mode: every one of these APIs treats the input
*string* as instructions, not data. Validating the JSON wrapper
around the payload does nothing — the danger is what's inside the
string the parser then evaluates.

## Bad example

```ts
// Repro paraphrased from DVNA `core/appHandler.js`. Direct RCE
// when an attacker posts the documented node-serialize payload.

import express from "express";
import serialize from "node-serialize";
import yaml from "js-yaml";
import vm from "vm";

const app = express();
app.use(express.json());

app.post("/import", (req, res) => {
  const obj = serialize.unserialize(req.body.payload); // RCE
  res.json({ obj });
});

app.post("/yaml", (req, res) => {
  const cfg = yaml.load(req.body.config); // RCE — unsafe schema
  res.json({ cfg });
});

app.post("/run", (req, res) => {
  vm.runInNewContext(req.body.script); // RCE — eval-as-a-service
  res.end();
});
```

## Good example

```ts
import express from "express";
import yaml from "js-yaml";
import { z } from "zod";

const app = express();
app.use(express.json());

// `yaml.safeLoad` resolves only the safe schema subset — no
// `!!js/function`, no `!!js/regexp`, no code execution.
app.post("/yaml", (req, res) => {
  const cfg = yaml.safeLoad(req.body.config);
  res.json({ cfg });
});

// JSON.parse is safe on its own; pair it with a schema to enforce
// the shape of the parsed value.
const Input = z.object({ name: z.string().max(64) });
app.post("/safe", (req, res) => {
  const parsed = Input.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "bad input" });
    return;
  }
  greet(parsed.data.name);
  res.json({ ok: true });
});
```

## How to fix

Replace the code-executing deserializer with a data-only parser
and validate the parsed shape with a schema:

- **`node-serialize.unserialize`** — there is no safe-list defence.
  Switch to `JSON.parse(...)` and validate the result with `zod`
  (or `valibot`, `arktype`). If you genuinely need to serialise
  functions across processes, transport them as named handler
  identifiers and look them up server-side from a registry.
- **`js-yaml`'s `yaml.load`** — call `yaml.safeLoad(...)`. In
  newer `js-yaml` releases the `load` API takes a `schema`
  option; pass `FAILSAFE_SCHEMA` or `CORE_SCHEMA` for equivalent
  safety.
- **`vm.runInNewContext` / `runInThisContext` / `runInContext`** —
  do not pass request input here at all. If you need a sandboxed
  expression language, use a purpose-built one (`expr-eval`,
  `jsep` + a custom evaluator) and never `vm`.

## What Stryx recognizes

Recognised as a sink (will fire on body-tainted first arg):

- `<x>.unserialize(...)` — receiver name unconstrained.
- Bare-ident `unserialize(...)` after destructured import.
- `yaml.load(...)` / `jsyaml.load(...)` / `YAML.load(...)`.
- `vm.runInNewContext(...)` / `vm.runInThisContext(...)` /
  `vm.runInContext(...)`.

Explicitly **not** recognised as a sink:

- `JSON.parse(...)` — never executes code. Flagging it would
  produce massive FPs on every Express body-parser usage.
- `yaml.safeLoad(...)` — the documented safe variant of
  `js-yaml`. The matcher discriminates on the *property* name
  (`load` fires, `safeLoad` does not).
- `vm.compileFunction(...)` — dangerous but deferred to a future
  slice.
- `libxmljs.parseXml(value, { noent: true })` (XXE) — the
  options-arg shape was judged out-of-scope for the v1 slice.

## Taint signature

| Field | Value |
|---|---|
| Source labels | `UserInput` (body / query / params / `searchParams`) |
| Sink ids | `deserialize.unserialize` (node-serialize), `deserialize.yamlLoad` (js-yaml unsafe load), `deserialize.vmRun` (vm.runInX). |
| Sanitizers recognized | None for slice 1. The canonical safe path is *use a different API* (`yaml.safeLoad`, `JSON.parse` + schema) — recognised by absence (a non-sink call carries no taint). |
| Scope | `SingleFile` |

## Detection logic

1. Walk every call expression. The sink recogniser activates on
   one of the shapes listed in "What Stryx recognizes".
2. The first argument is the payload being deserialized. The
   rule runs the standard body-taint walk on it.
3. If the argument is body-tainted, emit a Critical Finding at
   the call span.

The rule is single-file by design: every recognised sink is direct
RCE, so handler-local taint flow is already a high-signal finding.
Helper-routed cases (handler → imported helper → `unserialize`)
are deferred to a future cross-file slice if real fixtures motivate
it.

## Known false positive zones

- **A custom utility method named `unserialize`** on any
  receiver — the matcher does not constrain the receiver
  identifier because `node-serialize` is commonly aliased.
  → `// stryx-disable-next-line flow/insecure-deserialize -- not node-serialize`.
- **A non-yaml object exposing a `load` method** — the receiver
  guard restricts the `load` shape to `{yaml, jsyaml, YAML}`, so
  this case should not fire. If your code aliases `js-yaml` to a
  different identifier (e.g. `import * as y from "js-yaml"; y.load(...)`),
  the call will be missed (a *false negative*); the canonical
  fix is to rename or to flag the variant explicitly.
- **`yaml.load(constant)` with no request data** — slice 1's
  body-taint walk produces no finding when the argument is a
  constant or contains only constants. The good example above
  is silent.

## LLM escalation prompt (Layer 3)

Not applicable — this rule is fully deterministic at the AST
layer. The sink shapes are small and stable; LLM escalation is
reserved for shape-uncertain validators in the validation-flow
rules.

## Performance characteristics

- AST analysis: ~0.3ms per file (single-file slice 1; same shape
  as `flow/path-traversal` and `flow/command-injection-via-exec`
  slice 1).

## Configuration

```toml
[rules."flow/insecure-deserialize"]
severity = "critical"
```

## Suppressing this rule

Inline:
```ts
// stryx-disable-next-line flow/insecure-deserialize -- reason
```

File-level:
```ts
// stryx-disable flow/insecure-deserialize
```

Project-level (`stryx.toml`):
```toml
[rules]
disabled = ["flow/insecure-deserialize"]
```

## See also

- OWASP A08:2021 — Software and Data Integrity Failures
- CWE-502 — Deserialization of Untrusted Data
- `node-serialize` advisory history — RCE via the `_$$ND_FUNC$$_`
  marker has been public since 2017 and the package remains on
  npm.
- `js-yaml` security notes — `load` vs `safeLoad` schema scope.
- Node.js `vm` docs — the documented warning that `vm` is *not* a
  security boundary.
- Companion rules: `flow/command-injection-via-exec` (the same
  RCE consequence reached through `child_process` rather than a
  deserializer).

## History

| Version | Change |
|---|---|
| v0.4.0 | Initial single-file slice — body source → node-serialize `unserialize`, js-yaml `yaml.load`, and Node `vm.runInX` sinks. Severity Critical. No sanitiser recognition; `yaml.safeLoad` is recognised as safe by exclusion from the sink set. |
