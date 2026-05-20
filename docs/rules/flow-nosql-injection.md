# `flow/nosql-injection`

> Catches untrusted request input flowing into a MongoDB query
> filter document, where the attacker can substitute a query
> operator (`{$gt: ""}`, `{$ne: null}`, `{$where: "..."}`, `$regex`)
> in place of the scalar the developer expected.

## Metadata

| Field | Value |
|---|---|
| Rule ID | `flow/nosql-injection` |
| Status | experimental |
| Severity | high |
| Frameworks | Express, NestJS, generic Node + `mongodb` / Mongoose |
| Default | enabled |
| Added in | v0.4.x |

## What this rule catches

MongoDB filter documents are *structurally* dynamic — the driver
accepts any object as a filter, and operator-prefixed keys
(`$gt`, `$ne`, `$where`, `$regex`, …) change the matching
semantics. If the application reads a body field, expects a
string, and splices it into a filter as `{ login: req.body.login }`,
the attacker can send `{"login": {"$gt": ""}}` instead — the
*whole object* becomes the value of `login`, and `$gt: ""` matches
every document. The login check stops being an equality check at
all; the first row in the collection is returned.

The same class hits every "filter" path: `find` / `findOne` reads
expose data; `updateOne` / `updateMany` / `replaceOne` /
`deleteOne` / `deleteMany` writes target arbitrary rows;
`aggregate` and `countDocuments` carry the injection through
pipeline stages. On `$where` the operator is even worse — it
takes a JavaScript expression evaluated inside the database
engine.

## Why this happens

The `mongodb` driver and Mongoose accept *any* object as a filter,
so the safe path is not enforced by the API. Express tutorials
canonically read `req.body.login` and pass it directly to
`db.collection('users').findOne({ login: req.body.login })`;
TypeScript's structural types describe what the developer *meant*
but do nothing at runtime to keep a `{$gt: ""}` payload out.
NestJS controllers that take `@Body() body: SomeDto` without a
ValidationPipe (or with `transform: false`) have the same
property — the type annotation is documentation, not enforcement.

## Bad example

```ts
// Express + mongodb driver — login bypass.
import type { Request, Response } from "express";

export function login(req: Request, res: Response) {
  db.collection("users").findOne(
    { login: req.body.login, password: req.body.password },
    (err, user) => res.json({ user }),
  );
}
```

Attacker POSTs `{"login": {"$gt": ""}, "password": {"$gt": ""}}`.
The filter becomes `{ login: {$gt: ""}, password: {$gt: ""} }`,
which matches the first user in the collection. The handler
returns that user as if the credentials had been verified.

## Good example

```ts
// Same handler, coerce both fields to strings before the filter
// is built. `String({$gt: ""})` collapses to "[object Object]",
// which matches no real login.
export function login(req: Request, res: Response) {
  db.collection("users").findOne(
    {
      login: String(req.body.login),
      password: String(req.body.password),
    },
    (err, user) => res.json({ user }),
  );
}
```

Or — preferred — validate the body shape with a schema:

```ts
import { z } from "zod";

const Login = z.object({
  login: z.string().min(1),
  password: z.string().min(1),
});

export function login(req: Request, res: Response) {
  const parsed = Login.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid body" });
    return;
  }
  const { login, password } = parsed.data;
  db.collection("users").findOne({ login, password }, /* ... */);
}
```

## How to fix

Coerce each field to its expected scalar type before it reaches
the filter (`String(x)`, `Number(x)`, `Boolean(x)`), or — better —
validate the request body with a schema library (zod, joi,
class-validator, valibot, yup) so non-scalar payloads are rejected
at the boundary and the values that reach the query are provably
the type the type system claims they are.

The fix lives at the *handler* level, not at the database call.
Coercion or schema validation must run on the bound that crosses
the trust boundary (the body) before any property reaches the
collection method.

Do not try to recursively strip `$`-prefixed keys from the body.
That approach misses nested operator injection, false-negatives
on legitimate `$`-key payloads, and depends on a denylist that
the driver vendor can extend at any time.

## What Stryx recognizes

Recognised as the sink:

- `<x>.find(<obj>, ...)`, `<x>.findOne(<obj>, ...)`,
  `<x>.updateOne(...)`, `<x>.updateMany(...)`,
  `<x>.deleteOne(...)`, `<x>.deleteMany(...)`,
  `<x>.replaceOne(...)`, `<x>.aggregate(...)`,
  `<x>.countDocuments(...)`, plus the legacy
  `<x>.update(...)` / `<x>.remove(...)` / `<x>.count(...)`.
- Receiver `<x>` may be a bare identifier (`db`, `User`,
  `UserModel`), a member chain (`mongoose.models.User`), or a
  call expression (`db.collection('users')`,
  `mongoose.model('User')`).
- The first argument **must** be an object literal `{...}`. This
  is the load-bearing gate that filters out
  `Array.prototype.find(callback)`.

Recognised as a fix (no finding emitted):

- The same call shape, but with the body field wrapped in
  `String(...)`, `Number(...)`, or `Boolean(...)` — the wrapper
  is not a body source, so the property value is no longer
  tainted.
- A zod / joi / class-validator schema run on `req.body`
  upstream, where the destructured validated data — *not* the
  body itself — flows into the filter.
- A filter built from static values only (no body taint anywhere
  in the object expression).

Not recognised as a fix:

- TypeScript `as` / `satisfies` annotations on `req.body`.
  Type annotations do not validate runtime payloads.
- Manual `delete` of `$`-prefixed keys from `req.body`. This is
  a denylist and misses nested cases.

## Taint signature

| Field | Value |
|---|---|
| Source labels | `UserInput` (`req.body`, `req.query`, `req.params`, `c.req.json()`, NestJS `@Body()` / `@Query()` / `@Param()` decorated parameters) |
| Sink ids | `mongo.query` — MongoDB collection methods that take a filter document as their first argument (`find` / `findOne` / `updateOne` / `updateMany` / `replaceOne` / `deleteOne` / `deleteMany` / `aggregate` / `countDocuments` / legacy `update` / `remove` / `count`) |
| Sanitizers recognized | Scalar-coercion constructors (`String(...)`, `Number(...)`, `Boolean(...)`) implicitly: they are not body sources, so a tainted value wrapped in one stops carrying taint into the filter property. Slice 1 does not yet model schema validators as explicit sanitisers — the parser-sanitiser substrate covers them for sibling rules and lands here in a follow-up. |
| Scope | `SingleFile` |

## Detection logic

1. Walk every call expression. The sink recogniser activates when
   the callee is `<receiver>.<method>` with `<method>` one of the
   recognised collection methods *and* `<receiver>` is an
   identifier, member chain, or call expression.
2. The recogniser additionally requires the call's first argument
   to be an object literal `{...}`. This single gate eliminates
   the entire `Array.prototype.find(callback)` false-positive
   class (callbacks are function expressions, not object
   expressions).
3. For each matched call, walk the property values of the
   first-argument object literal. If any property value carries
   body taint (a body source, a body-tainted binding, a member
   chain rooted at one, etc.), emit a High-severity Finding at
   the call span — labelled with the offending property name.

This is a single-file rule for slice 1. Cross-file flows where
the handler hands `req.body` to a helper that does the
`collection.findOne` call are out of scope — the
`flow/unvalidated-body-to-db` rule continues to cover the
general body-to-database flow, and the cross-file extension for
operator-injection specifically lands in a follow-up slice.

## Known false positive zones

- **`Array.prototype.find(callback)` and similar `.find(...)` /
  `.findOne(...)` shapes on non-database objects.** Any
  `<ident>.find(...)` call shape is recognised conservatively,
  but the load-bearing object-literal gate on the first argument
  filters the common Array/Map/Set cases out: those take a
  *callback function*, not an object literal.
  → If you have a custom `.find({...})` API on a non-database
  object that happens to take a query object, suppress per line
  with `// stryx-disable-next-line flow/nosql-injection -- not a mongo query`.
- **Lodash `_.find(arr, {k: v})`** — the shorthand matches by
  property/value and *does* take an object literal as its second
  argument. Lodash's `find` is `_.find(...)`, not
  `<receiver>.find(...)`, so the bare `_.find` shape does not
  match. The `arr.find({...})` chain shape would match — that
  combination is rare, and we accept the FP risk here.
  → Suppress with the inline comment above.
- **Static filter with body data buried in a non-property
  position** (e.g. `{ id: STATIC, sort: req.body.dir }` where
  `dir` controls a sort field). Sort fields are not operator-
  injectable in the same sense, but slice 1 will still fire if
  the property value carries body taint. Treat this as a
  legitimate hit and coerce the value, or restructure the call
  to use the explicit `sort` option outside the filter document.

## LLM escalation prompt (Layer 3)

Not applicable — this rule is fully deterministic at the AST
layer.

## Performance characteristics

- AST analysis: ~0.3ms per file. The hot path is the call-
  expression walk; the sink predicate is a static-string match on
  the method name plus an `Argument::ObjectExpression` matches.

## Configuration

```toml
[rules."flow/nosql-injection"]
severity = "high"        # override default
```

## Suppressing this rule

Inline:
```ts
// stryx-disable-next-line flow/nosql-injection -- reason
```

File-level:
```ts
// stryx-disable flow/nosql-injection
```

Project-level (`stryx.toml`):
```toml
[rules]
disabled = ["flow/nosql-injection"]
```

## See also

- OWASP A03:2021 — Injection
- CWE-943 — Improper Neutralization of Special Elements in Data
  Query Logic
- MongoDB query selectors documentation (`$gt`, `$ne`, `$where`,
  `$regex`)
- NodeGoat — OWASP project demonstrating MongoDB operator
  injection in an Express + Mongo login handler
- Related rule: `flow/unvalidated-body-to-db` — the broader
  body-to-database flow this rule specialises for the
  operator-injection case

## History

| Version | Change |
|---|---|
| v0.4.x | Initial single-file slice — body-tainted property values inside MongoDB filter object literals. Severity High. No cross-file taint summary yet. |
