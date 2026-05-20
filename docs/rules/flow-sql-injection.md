# `flow/sql-injection`

> Catches untrusted request input flowing into a raw-SQL sink
> (Prisma `$queryRawUnsafe`, Drizzle `sql.raw`, node-postgres /
> mysql2 `.query(<sql>, ...)`) where the SQL string is built
> dynamically from the body.

## Metadata

| Field | Value |
|---|---|
| Rule ID | `flow/sql-injection` |
| Status | experimental |
| Severity | critical |
| Frameworks | nextjs >= 13, generic Node (single-file + cross-file slice 2) |
| Default | enabled |
| Added in | v0.2 (Phase 2 of [ADR 0011](../decisions/0011-v01-to-v02-transition.md), Track B) |

## What this rule catches

SQL injection is the canonical critical web vulnerability: the
attacker submits a value the application splices verbatim into a
SQL string, which the database then parses and executes. The
attacker can read or modify any data the application can access,
escalate to operating-system command execution on some database
configurations, and pivot to lateral access on most.

The whole class is preventable by *parameterised queries*: the
SQL string is fixed and the user-supplied values are passed
separately as bind parameters. Every supported ORM in the
TypeScript ecosystem has a safe-by-default parameterised path.

The trap is that every ORM also exposes a *raw* escape hatch for
when the developer "needs to do something the typed API can't
express." Stryx flags request-body data reaching these escape
hatches:

- Prisma — `prisma.$queryRawUnsafe(query)` / `prisma.$executeRawUnsafe(query)`.
  The `Unsafe` suffix is the explicit opt-out from parameterisation.
  The non-`Unsafe` tagged-template variants (`prisma.$queryRaw\`\``
  and `prisma.$executeRaw\`\``) generate parameterised SQL and are
  safe; they are not flagged.
- Drizzle — `sql.raw(query)` is the escape hatch from the
  parameterised `sql\`\`` tagged template. The tagged template
  itself is safe.
- node-postgres / mysql2 — `pool.query(sql, params)` /
  `client.query(sql, params)` / `db.query(sql, params)`. The
  first argument is the SQL string. If that string is a literal
  or a hardcoded constant, the call is safe (any user-supplied
  values flow through `params`). If the string is a template
  literal with a body-tainted interpolation, or a string concat
  with body data, the call is a SQL-injection sink.

## Why this happens

Raw-SQL escape hatches are tempting when the typed API feels too limited:
dynamic `ORDER BY` columns, dynamic `WHERE` clauses, full-text search
across multiple tables, optional join conditions. The unsafe pattern is
`pool.query(\`SELECT ... WHERE col = ${user.value}\`)` or
`prisma.$queryRawUnsafe(\`SELECT ... ${user.column}\`)` — it compiles,
runs, and often passes tests with hardcoded inputs.

The missing boundary is that the attacker controls `user.value`; SQL text
must stay static and values must be bound separately.

## Bad example

```ts
// Repro: request input controls a raw ORDER BY fragment.

import type { NextRequest } from "next/server";
import { prisma } from "@/lib/db";

export async function POST(req: NextRequest) {
  const { sortBy } = await req.json();
  const users = await prisma.$queryRawUnsafe(
    `SELECT id, email FROM "User" ORDER BY ${sortBy} ASC`,
  );
  return Response.json(users);
}
```

`sortBy` can be `1; DROP TABLE "User"; --` (or any other SQL
fragment). Postgres parses and executes whatever the attacker
sends.

## Good example

```ts
import type { NextRequest } from "next/server";
import { prisma } from "@/lib/db";

const ALLOWED_SORTS = new Set(["email", "createdAt", "id"]);

export async function POST(req: NextRequest) {
  const { sortBy } = await req.json();
  if (!ALLOWED_SORTS.has(sortBy)) {
    return Response.json({ error: "invalid sort" }, { status: 400 });
  }
  // Prisma's tagged-template variant generates parameterised SQL.
  // The column identifier still has to be allow-listed (above)
  // because identifiers can't be bound — only values can.
  const users = await prisma.$queryRaw`
    SELECT id, email FROM "User" ORDER BY ${Prisma.raw(sortBy)} ASC
  `;
  return Response.json(users);
}
```

For column-identifier substitution the developer still has to
allow-list (parameterisation only binds *values*, not
identifiers), but the surrounding query and any user-supplied
filter values flow through Prisma's tagged-template parameterised
path.

## How to fix

Prefer the ORM/query-builder API that binds values separately from the
SQL string. If raw SQL is unavoidable, keep the SQL template static and
pass user-controlled values through bind parameters or the ORM's
parameterised tagged template. For dynamic identifiers such as `ORDER BY`
columns, map request input to a constant allow-list before it reaches the
query.

Do not "sanitize" SQL by escaping strings yourself. The safe shape is
parameterisation for values and allow-listing for identifiers.

## What Stryx recognizes

Recognized as safe:

- Prisma's non-unsafe tagged-template calls such as
  `prisma.$queryRaw\`...\``.
- Drizzle's parameterised `sql\`...\`` template when request values are
  interpolated as bind values.
- `pg` / `mysql2` calls where the SQL string is static and request data
  is passed through the parameter array.

Lower-risk pattern documented but not fully recognized as a sanitizer in
slice 1:

- Identifier allow-lists checked before a raw identifier is used.

Not recognized as safe:

- `prisma.$queryRawUnsafe(...)` or `$executeRawUnsafe(...)` with request
  data in the SQL string.
- `sql.raw(...)` with request data.
- Template strings or string concatenation that splice request data into
  the SQL text.
- TypeScript casts or comments claiming a value is safe.

## Taint signature

| Field | Value |
|---|---|
| Source labels | `UserInput` (body / query / headers / `searchParams`) |
| Sink ids | `sql.queryRawUnsafe` (Prisma `$queryRawUnsafe` / `$executeRawUnsafe`), `sql.raw` (Drizzle `sql.raw`), `sql.query` (node-postgres / mysql2 `pool.query` / `client.query` / `db.query` / `connection.query`) |
| Sanitizers recognized | None for slice 1. The canonical safe path is the parameterised tagged-template (`prisma.$queryRaw\`\``, `sql\`\``) — those shapes are *not flagged* because the rule's sink-recogniser doesn't match them in the first place. Allow-listing identifiers via `Array.includes` / `Set.has` against a hardcoded list is a future sanitiser recognition target. |
| Scope | `SingleFile` + `CrossFile` |

## Detection logic

1. Walk every call expression. The sink-recogniser activates on
   one of the recognised path shapes:
   - `<x>.$queryRawUnsafe(<sql>, ...)` (any receiver).
   - `<x>.$executeRawUnsafe(<sql>, ...)`.
   - `<x>.raw(<sql>, ...)` where `<x>` is the bare identifier
     `sql` (Drizzle).
   - `<x>.query(<sql>, ...)` where `<x>` is one of the
     conventional database-connection identifiers (`pool`,
     `client`, `db`, `connection`).
2. For the matched call, the *first* argument is the SQL
   string. The rule walks it via the standard body-taint walk.
   String literals and identifiers that aren't tainted produce
   no finding.
3. If the SQL string is body-tainted, emit a critical-severity
   Finding at the call span.
4. **Cross-file (slice 2).** The extract pass simulates each
   exported function with one parameter pre-tainted and records
   `ParamFlow::reaches_sql_sink_unsanitized` when the simulation
   observes a raw-SQL sink. The run pass walks call sites; when a
   tainted argument flows into a reach-flagged parameter slot of a
   callee resolved via the project index, a Critical finding is
   emitted at the call site. Helpers that switch to the
   parameterised tagged-template form internally drop the reach
   flag and suppress the call-site finding.

## Known false positive zones

- **Custom `.query()` method on a non-database object** that
  happens to be assigned to one of the conventional names
  (`pool`, `client`, `db`, `connection`). Slice 1's recogniser is
  path-shape only and would flag such calls if a tainted value
  flowed in.
  → Suppress per line with `// stryx-disable-next-line flow/sql-injection -- not a SQL connection`.
- **Allow-listed dynamic identifiers** (`ORDER BY ${col}` where
  `col` has been checked against a hardcoded allow-list).
  Slice 1 doesn't recognise the allow-list pattern, so the rule
  fires. The good example above shows the recommended fix
  (parameterised tagged template + allow-list check); both
  defences land together.
  → Future slice will recognise `Set.has` / `Array.includes`
  narrowing across the rule.

## LLM escalation prompt (Layer 3)

Not applicable for slice 1 — fully deterministic AST analysis.
Future slices may emit UncertainZones when the SQL argument is
sourced from a function call whose return-type information would
disambiguate the safety boundary.

## Performance characteristics

- AST analysis: ~0.3ms per file (single-file slice 1; same shape
  as `flow/path-traversal` and `flow/ssrf-via-fetch` slice 1).
- Cross-file slice 2 adds one per-export per-param simulation
  during the extract pass; reach-only contribution, no shape
  walks.

## Configuration

```toml
[rules."flow/sql-injection"]
severity = "critical"
```

## Suppressing this rule

Inline:
```ts
// stryx-disable-next-line flow/sql-injection -- reason
```

File-level:
```ts
// stryx-disable flow/sql-injection
```

Project-level (`stryx.toml`):
```toml
[rules]
disabled = ["flow/sql-injection"]
```

## See also

- OWASP A03:2021 — Injection
- CWE-89 — Improper Neutralization of Special Elements used in
  an SQL Command
- Prisma docs — Raw database access (`$queryRaw` vs `$queryRawUnsafe`)
- Drizzle docs — `sql\`\`` vs `sql.raw`
- node-postgres parameterised query guide

## History

| Version | Change |
|---|---|
| v0.2 | Initial single-file slice — body source → Prisma `$queryRawUnsafe` / `$executeRawUnsafe`, Drizzle `sql.raw`, node-postgres / mysql2 `<conn>.query` sinks. Severity Critical. No sanitiser recognition. |
| v0.2.1 | Slice 2 — cross-file taint via `ExportedFunctionSummary::reaches_sql_sink_unsanitized`. Route handler → imported helper → raw-SQL call chains now fire at the call site with Critical severity. Helper that switches to the parameterised tagged-template form (`prisma.$queryRaw`...``) suppresses the call-site finding. |
