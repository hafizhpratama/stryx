# ADR 0010 — External library summaries via token grammar

- **Date**: 2026-05-10
- **Status**: Proposed
- **Decider**: Hafizh Pratama
- **Supersedes**: none
- **Refines**: [ADR 0003](0003-cross-file-and-taint-as-core.md), [ADR 0005](0005-taint-aware-cache-keys.md), [ADR 0006](0006-shape-lattice-taint-summary.md), [ADR 0008](0008-taint-step-trait-substrate.md)

## Context

Stryx today summarises only **in-project functions**. The
`extract` pass walks every TypeScript file in the scan root,
runs the per-rule visitor, and writes a per-function summary
into `ProjectIndex` (`crates/stryx_index/src/lib.rs`). At call
sites, `ProjectIndex::resolve_summary` looks up the callee's
summary if the import points to an in-project file.

Imports that resolve to `node_modules` are silent gaps. The
import-resolver returns `None` for bare specifiers (`axios`,
`zod`, `lodash`, `crypto`, `prisma`, ...), the call-site visitor
falls back to its conservative default (any tainted argument
flows through), and we lose precision in two directions:

### Problem 1: missing source recognition

```ts
import axios from "axios";
const { data } = await axios.get(`/api/users/${userId}`);
await prisma.user.create({ data });
```

`axios.get`'s return value is shaped — `{ data: any, status, headers,
config, ... }`. Today Stryx treats the destructured `data` as the
result of an opaque call with a tainted-input argument, so
`data` is whole-value tainted. The finding fires at High severity
on `prisma.user.create({ data })`. The right behaviour: recognise
that `axios.get` returns `{ data: <tainted-from-arg-0>, ... }`
and that `data` carries `Tainted+Bot` only because the URL
substring was tainted. A finer summary would mark the response's
`data` field as needing a parser and flag the *missing
validation*, not the call shape itself.

### Problem 2: missing sanitiser recognition

```ts
import { z } from "zod";
const schema = z.object({ id: z.string() });
const data = schema.parse(req.body);
await prisma.user.create({ data });
```

`zod`'s `schema.parse()` is a body-validating sanitiser; the
return value is statically known to match the schema. Today's
`is_sanitizer_call` recogniser
(`crates/stryx_rules/src/flows/unvalidated_body_to_db.rs:1529`)
hardcodes a small set of zod/valibot/yup recognition patterns
inline. Adding a new validator library (`@sinclair/typebox`,
`arktype`, `superstruct`, `runtypes`) requires a Rust edit plus
a release. Five rules with their own sanitiser hardcodings
multiplies that surface (Problem 2 of [ADR 0008](0008-taint-step-trait-substrate.md)).

### Problem 3: missing sink recognition

```ts
import { exec } from "child_process";
exec(`grep ${userInput} /var/log`);
```

`exec` is an obvious command-injection sink; we don't recognise
it. The hardcoded sink list in
`unvalidated_body_to_db.rs:1633–1675` covers Prisma, Drizzle, and
TypeORM — DB sinks only. Adding shell, response, and crypto sinks
means another N×M of hardcoded predicate Rust code, multiplied
by the rule that consumes them.

### Problem 4: scaling beyond Next.js

The CLAUDE.md roadmap targets Hono, Express, and NestJS in
Phase 3. Each framework has its own request-source helpers
(`c.req.json()` for Hono, `req.body` for Express, decorator-driven
parameter injection for Nest), its own response sinks
(`c.json()`, `res.send()`, `@Res()` decorator targets), and its
own validation idioms.

If each framework requires a Rust pull request to a hardcoded
list, framework breadth becomes a release-cadence problem.
Indie devs and vibe coders — the priority audience per
CLAUDE.md — adopt new frameworks faster than a release cycle
can keep up.

### What the deep-dive showed

The competitive review (May 2026) flagged this as the **largest
single competitive gap** for Stryx. CodeQL ships thousands of
npm package summaries via YAML-encoded data extensions
(`Argument[N].Member[foo] -> ReturnValue, taint`). Semgrep ships
rule packs maintained outside the engine. Both treat external
summaries as **data**, not **code**. Stryx today treats them
as **absent**.

## Architectural question

How do we ship external library summaries — for `axios`, `zod`,
`prisma`, `crypto`, `child_process`, dozens more — as data, while
honouring CLAUDE.md hard rule #5 ("no rule DSL until 30+ rules
exist") and preserving the content-keyed cache contract from
ADR 0005?

The resolution: the rule DSL prohibition applies to **rule
authoring** (how a rule like `flow/unvalidated-body-to-db` is
declared). It does *not* apply to **library models** — purely
descriptive summaries of what an external function does at the
taint level. Library models are not rules; they're inputs to
the rules the engine already runs.

CodeQL makes the same distinction. Their rule-equivalent (QL
predicate-based queries) is code. Their library models are data
(YAML model packs). The two layers are independent.

## Options considered

### Option A — TOML token grammar in `stryx.toml` (chosen)

Define a small token grammar for "value paths through a function":

```
ValuePath := "Argument[" Number ("." Step)* "]"
           | "ReturnValue" ("." Step)*
Step      := "Member[" Identifier "]"
           | "Member[" String "]"
           | "ArrayElement"
           | "AnyMember"
```

`Member[foo]` is `Offset::Field("foo".into())`; `Member["x-key"]`
is the same with a quoted-string key (for header maps with
hyphenated names); `ArrayElement` is `Offset::Index(0)` with
"any-element" semantics; `AnyMember` is `Offset::Any`. The
grammar is a near-direct rendering of CodeQL's access-path
strings, structured for our existing `Cell` lattice.

A summary entry says "taint flows from this value-path on input
to that value-path on output, with this kind":

```toml
[summary."axios.get"]
flows = [
  { from = "Argument[0]", to = "ReturnValue.Member[config].Member[url]", kind = "value" },
]

[summary."zod.ZodSchema.parse"]
flows = [
  { from = "Argument[0]", to = "ReturnValue", kind = "sanitised" },
]

[summary."child_process.exec"]
sinks = [
  { at = "Argument[0]", label = "command-injection", severity = "high" },
]

[summary."express.Request.body"]
sources = [
  { at = "Member[*]", label = "user-input" },
]
```

`kind = "value"` preserves taint without sanitising (the value
literally flows through). `kind = "taint"` propagates taint as
a flow step (the input *contributes to* the output). `kind =
"sanitised"` clears taint on the output (the function is a
validator).

The loader at scan startup:

1. Reads `stryx.toml` (project-local) plus `~/.config/stryx/
   summaries.toml` (user-global) plus the bundled
   `crates/stryx_rules/data/summaries/*.toml` (vendored defaults
   shipped with the binary).
2. Parses each `[summary."<callee>"]` block via `serde + toml`.
3. For each `flows` entry, parses the `from`/`to` value-path
   strings into `(Vec<Offset>, OffsetRoot)` where `OffsetRoot`
   is `ArgumentRoot(usize)` or `ReturnRoot`.
4. Constructs an `ExportedFunctionSummary` value: each
   `Argument[N]` source-side path becomes a `ParamFlow` entry
   with the corresponding `param_shape`; each `ReturnValue`
   target gets folded into `return_shape`.
5. Each summary is keyed by the qualified callee path
   (`axios.get`, `child_process.exec`, etc.) and inserted into a
   new `ProjectIndex.external_summaries: HashMap<QualifiedName,
   ExportedFunctionSummary>` map.
6. The cache key (ADR 0005) gains a `summaries_digest`
   component: `blake3` over the canonicalised content of all
   loaded summary files. Content change ⇒ all in-project
   summaries invalidate (one-time cost; no per-package
   granularity needed at v0.4).

Call-site resolution gains an external-summary fallback
(`stryx_index/src/lib.rs:222 resolve_summary`):

1. Resolve the import to an in-project path → return that
   summary.
2. Resolve the import to a bare specifier → look up the
   qualified callee in `external_summaries`. Match on
   `<package>.<exported>` plus class-prefixed forms
   (`<package>.<class>.<method>`). Return the matched summary
   if any.
3. Otherwise fall back to today's conservative default (any
   tainted arg flows through).

Sources, sinks, and sanitisers declared in summary files
register `StepKind` instances against the qualified name at
load time, per [ADR 0008](0008-taint-step-trait-substrate.md).
The runtime dispatch path is the same closed-enum match; the
*input* to the dispatch is what changes.

**Pros:**

- **No DSL for rule authoring.** CLAUDE.md rule #5 holds.
  Rules stay in Rust. The TOML schema describes *function
  behaviour*, not *rule logic*.
- **Reuses every existing primitive.** `Offset`, `Cell`,
  `ParamFlow`, `ExportedFunctionSummary`, `ProjectIndex`,
  `StepKind` (per ADR 0008) — all unchanged. The token
  grammar parses *into* these types.
- **Bundled defaults plus user overrides.** Stryx ships a
  starter library — axios, zod, prisma client, lodash, crypto,
  child_process, fs/promises, web-fetch — under
  `crates/stryx_rules/data/summaries/` (vendored, included via
  `include_str!` so binaries ship a complete model out of the
  box). User can override or add via `stryx.toml`.
- **Cache key contract holds.** ADR 0005's content-keyed cache
  extends with a single `summaries_digest` field; same one-time
  invalidation pattern as the Phase 1→Phase 2 transition.
- **Determinism preserved.** TOML iteration order is enforced
  at load time (canonicalise into `BTreeMap`); summaries
  serialise the same byte-for-byte across runs.
- **Type-safe loader.** `serde` + `toml` + a small parser for
  the value-path strings catches schema errors at startup
  with file:line diagnostics. No silent runtime drift.
- **Composes with HOF (slice 3.6) and guard barriers (ADR 0009).**
  An external summary can declare a sanitised-when-truthy
  result (`{ from = "Argument[0]", to = "ReturnValue.Member[data]",
  kind = "sanitised", when = "ReturnValue.Member[success]" }`)
  — slice 9.7's schema-discriminant pattern gets a declarative
  form for libraries that ship their own.

**Cons:**

- **Token grammar surface to maintain.** A fixed set of step
  types (`Member`, `ArrayElement`, `AnyMember`, plus root
  forms) plus the kind tags. Schema versioning is a real
  concern — a v0.4 summary file may not load against a v0.5
  engine if the grammar changes. Mitigated by a `version = 1`
  required field per file with explicit diagnostics on
  mismatch.
- **Quality vs quantity tradeoff.** Bundled defaults can be
  wrong (mis-modelled async chain, missed sanitisation).
  Wrong summary is worse than missing summary — a wrong
  sanitiser hides real findings. Mitigated by:
  - Vendored summaries have unit tests in
    `crates/stryx_rules/tests/summaries.rs` exercising each
    `flows`/`sources`/`sinks`/`sanitisers` entry against a
    real-world fixture.
  - User can disable a bundled summary via `disable =
    ["axios.get"]` in their `stryx.toml`.
- **Library-version drift.** `axios@0.27` and `axios@1.6`
  have different return-shape semantics (the response body
  was at `.data` in 0.x, still `.data` in 1.x — but `prisma`
  has changed sink shapes between 4.x and 5.x). The summary
  file declares the version range it applies to (`versions =
  ">=4.0.0 <6.0.0"`); load-time diagnostics warn on
  unmodelled-version usage.
- **Scope discipline.** A summary that's too eager (every
  function is a sink) destroys precision. The vendored set
  ships only well-known sources/sinks/sanitisers; community
  contributions go through a review gate analogous to
  `THIRD_PARTY_LICENSES.md`.

### Option B — Hardcoded Rust summaries in `stryx_rules`

Continue today's pattern: each new external library is a Rust
edit. `is_axios_get_call`, `is_zod_parse_call`, etc.

**Pros:**

- Type-safe at the call site.
- No new substrate to design.

**Cons:**

- Doesn't scale. Per Problem 4, every framework adoption is a
  release cycle.
- The N×M predicate-multiplication problem from ADR 0008
  applies here in spades: 50 packages × 5 rules = 250 hardcoded
  recognisers.
- Locks out community contributions for library coverage. The
  audience that needs the coverage most (indie devs adopting
  new packages weekly) can't help.

Rejected. ADR 0008's step-trait substrate addresses *rule-side*
duplication; library-side hardcoding scales worse than rule-
side and the same arguments apply.

### Option C — Full Semgrep-style YAML rule packs

Adopt Semgrep's rule format directly: rules and library models
both as YAML, with patterns expressed in a unified DSL.

**Pros:**

- Maximum declarativity. Rules and library models share a single
  schema.
- Trivial community contribution model.
- Compatible with Semgrep ecosystem (could reuse existing
  pattern packs — license-compatible ones).

**Cons:**

- **Violates CLAUDE.md rule #5.** Until 30+ rules ship, no DSL
  for rule authoring.
- Couples library-summary scope (this ADR) with rule-DSL scope
  (deferred to v0.5+). Pulls forward a v0.5 substrate decision
  with no v0.4 driver.
- Requires a pattern-matching engine — Semgrep's
  `Taint_spec_match.ml` is non-trivial and ships years of
  edge-case fixes.

Rejected for v0.4. **Reconsider at v0.5+** when rule-DSL
motivation independently justifies the substrate. At that point,
this ADR's TOML token grammar slots in as a subset of the YAML
rule schema (the `flows`/`sources`/`sinks` entries are exactly
the library-model subset of a full rule).

### Option D — Per-package npm distribution of summaries

Ship summaries via npm packages: `@stryx/axios-model`,
`@stryx/zod-model`, etc. User installs the ones they need;
Stryx loads them via the project's `node_modules`.

**Pros:**

- Independent versioning per package. `@stryx/axios-model@1.6`
  pins to `axios@1.6`.
- Discovery via npm search.
- Aligns with the priority audience's existing tooling (npm
  install).

**Cons:**

- Dependency on `npm install` ordering. Stryx wants to scan
  before install (`stryx scan` should work without
  `node_modules`). Library summaries shipped via npm don't
  load.
- One indirection layer (npm package → file path → load) where
  Option A has zero (vendored or `stryx.toml`-declared).
- Cache key contract complicates: a stale npm cache produces
  out-of-date summaries; we'd need to hash `node_modules/<pkg>/
  package.json` versions.

Rejected as the primary mechanism. **Adopted as a complement**:
v0.5+ can ship community summaries via npm packages that drop
TOML files into a known location at install time, picked up by
the existing loader. This ADR's substrate is the foundation;
npm distribution is one delivery channel atop it.

### Option E — LLM-derived summaries

When the engine sees an unknown external import, dispatch a
Layer 3 LLM call to derive a summary on-demand. Cache by
package+version+exported-name.

**Pros:**

- Covers any package automatically.
- Cache contract amortises cost.

**Cons:**

- LLM cost per uncached package can be substantial. A new
  scan against an unfamiliar codebase faces O(distinct
  imported callees) cold misses.
- Quality variance per LLM run. A wrong sanitiser hides real
  findings; the cache amplifies that wrongness across runs.
- Determinism contract (CLAUDE.md, `--no-llm`) requires the
  engine to function without LLM. So summaries must exist
  without LLM.
- Doesn't address Problems 2/3/4 architecturally — LLM
  summaries are a *fallback*, not a substrate.

Rejected as the primary mechanism. **Adopted as a complement**:
on first encounter with an unmodelled external callee, emit
an `UncertainZone` per call site for Layer 3 verification (ADR
0002). Summaries derived by LLM with high confidence are
*offered* to the user as suggested additions to their
`stryx.toml`, never auto-installed. This keeps the deterministic
mode (`--no-llm`) honest.

## Decision

**Option A — TOML token grammar in `stryx.toml` plus bundled
vendored defaults** is the v0.4 external-summary substrate.

Migration follows the slice discipline of prior ADRs: each
slice independently shippable, byte-identical-to-fallback when
no summary loads, reversible.

### Implementation slices

**Slice 10.1 — value-path token parser (no consumer):**

- New module `crates/stryx_index/src/external_summaries/grammar.rs`.
- `parse_value_path(s: &str) -> Result<(Root, Vec<Offset>),
  ParseError>` where `Root` is `ArgumentRoot(usize)` or
  `ReturnRoot`.
- Recogniser is a hand-rolled state machine (no `pest`, no
  `nom` — total grammar is ~200 LOC of recursive-descent over
  20-character strings; fewer dependencies, faster compile).
- Unit-tested against the documented grammar; round-trip
  property test (parse → render → parse identity).
- Shipped without consumers; OSS scan output unchanged.

**Slice 10.2 — `ExternalSummary` type + serde:**

- `crates/stryx_index/src/external_summaries/types.rs`:
  - `ExternalSummary { version: u32, callees: HashMap<QualifiedName, CalleeModel> }`
  - `CalleeModel { flows: Vec<FlowSpec>, sources: Vec<SourceSpec>,
    sinks: Vec<SinkSpec>, sanitisers: Vec<SanitiserSpec>,
    versions: Option<VersionRange>, disable: bool }`
  - `FlowSpec { from: ValuePath, to: ValuePath, kind: FlowKind }`
  - `FlowKind { Value, Taint, Sanitised }`
- `serde + toml` derive for load.
- Loader at `crates/stryx_index/src/external_summaries/loader.rs`
  reads three sources: vendored (via `include_str!`), user-
  global (`~/.config/stryx/summaries.toml`), project-local
  (`stryx.toml`'s `[summaries.*]` namespace). Project-local
  overrides user-global overrides vendored.
- Substrate-only; no `ProjectIndex` integration.

**Slice 10.3 — `ProjectIndex` integration (opt-in feature flag):**

- `ProjectIndex.external_summaries: HashMap<QualifiedName,
  ExportedFunctionSummary>`.
- `ExternalSummary → ExportedFunctionSummary` translator: each
  `FlowSpec`/`SourceSpec`/etc. becomes the corresponding
  `ParamFlow` and `return_shape` entries via the existing
  `Cell::merge_into` and shape-construction helpers.
- `resolve_summary` extended with the bare-specifier fallback.
- Behind `cfg(feature = "external_summaries")` until validation
  passes — bundled summaries can produce surprising findings
  on existing fixtures otherwise.

**Slice 10.4 — vendored starter pack:**

- Files in `crates/stryx_rules/data/summaries/`:
  - `axios.toml` — `axios.get`, `axios.post`, `axios.request`
    (response shape, URL-arg taint propagation)
  - `zod.toml` — `ZodSchema.parse`, `ZodSchema.safeParse`
    (sanitiser; safeParse return-shape with discriminant)
  - `child_process.toml` — `exec`, `execSync`, `spawn` (sinks)
  - `prisma.toml` — `findUnique`, `findFirst`, `findMany`,
    `count` (read-call return-shape — slice 8 is currently
    hardcoded; this migrates it)
  - `crypto.toml` — `randomBytes`, `randomUUID`
    (sanitiser/source distinction)
  - `next-server.toml` — `NextRequest.json`, `NextRequest.formData`,
    `NextResponse.json` (sources/sinks; today inlined in
    `flows/secret_to_response.rs` and `flows/unvalidated_body_to_db.rs`)
- Each TOML file ships with a colocated `*_test.rs` exercising
  each entry against a real-world fixture.

**Slice 10.5 — cache key extension (ADR 0005):**

- New field on the cache-key digest: `summaries_digest =
  blake3(canonical(merged_summaries))`.
- Canonical form: BTreeMap-sorted, all internal Vecs sorted,
  all FloatSpec normalised — same determinism contract as
  ADR 0006 shape canonicalisation.
- Existing summaries invalidate one-time on the v0.4 release.
  Documented in CHANGELOG.md as the same invalidation flavour
  as Phase 1→Phase 2.

**Slice 10.6 — `--summaries <path>` CLI flag:**

- `clap`-driven argument; appends additional summary files at
  load time. Useful for project-specific overrides outside the
  default `stryx.toml`.
- Multi-value: `--summaries lib1.toml --summaries lib2.toml`.

**Slice 10.7 — `--no-summaries` for deterministic comparison:**

- Disables the bundled vendored summaries and any user-supplied
  summaries. Behaviour reverts to v0.3.x (no external
  summaries). Useful for A/B comparison and for users debugging
  precision changes between releases.
- Required for the OSS validation diff at slice 10.4: the
  comparison baseline runs with `--no-summaries`.

**Slice 10.8 — LLM-suggested summary emission (ADR 0002 plug-in):**

- When Layer 3 escalates an `UncertainZone` for an unmodelled
  external callee and the LLM returns high-confidence taint
  flow, render the response into a TOML stanza and surface it
  via the `--suggest-summaries <path>` flag.
- User reviews and adds to their `stryx.toml`.
- Never auto-applied; always user-confirmed.

### Out of scope

- **Type-aware summary inference.** Using TypeScript declaration
  files (`.d.ts`) to derive flow specs automatically. Phase 4
  (deeper `oxc_semantic` use) territory.
- **Cross-package summary composition.** A summary that says
  "`prisma.user.findUnique` returns the row type from the
  schema" requires schema-aware reasoning; out of scope.
  Approximated by `ReturnValue.AnyMember` with `Tainted`.
- **Conditional summaries.** A summary that fires only when an
  argument is a literal vs a variable. Out of scope; covered
  by the `Sanitised + when` extension at slice 9.7's schema-
  discriminant model — *if* declared in the summary, *only*
  for `truthy`-shaped guards.
- **Summary versioning per package version.** A
  `VersionRange` field is recorded but not enforced beyond a
  diagnostic warning at slice 10.4. Full enforcement requires
  reading user `package-lock.json`/`pnpm-lock.yaml`/`yarn.lock`;
  deferred.
- **Importing CodeQL or Semgrep summaries directly.** License-
  compatibility and grammar-translation costs make this
  unattractive. We ship our own.

## Consequences

### Positive

- **External libraries become first-class.** Axios, zod,
  prisma client, child_process — all modelled, all
  consumable by every flow rule via the existing summary
  contract.
- **Community contribution path opens.** A user adds
  `arktype.toml` to their project; if it's well-modelled,
  they upstream it via PR; we vendor it. No Rust knowledge
  required to contribute summaries.
- **Framework breadth becomes a data problem, not a release
  problem.** Hono, Express, NestJS — each ships a `.toml`
  pack; the engine is unchanged.
- **Existing hardcoded recognisers migrate cleanly.** ADR 0008's
  `BodySource` and `PrismaWriteSink` step variants become
  `external_summaries` consumers; the inline predicate code
  retires. Slice 10.4 specifically migrates Prisma read-call
  recognition out of `expr_taint` and into the summary file.
- **Layer 3 becomes more focused.** LLM escalation handles
  unmodelled cases (slice 10.8 surfaces them as suggestions);
  modelled cases stay deterministic.
- **The `Argument[N].Member[foo]` token grammar is a stable
  public surface.** Future v0.5+ rule-DSL builds on it
  directly; no schema rework.

### Negative

- **Wrong summaries hide real findings.** The biggest risk.
  Mitigated by:
  - Mandatory unit tests per vendored summary entry.
  - `--no-summaries` for instant baseline comparison.
  - Per-summary disable in `stryx.toml`.
  - LLM-suggested summaries never auto-apply.
- **Summary maintenance burden.** Vendored packs need
  updates as upstream library APIs change. Dedicated
  `docs/summaries/<package>.md` for each vendored summary
  documenting the modelled version range.
- **Cache invalidates one-time at v0.4.** Same flavour as
  Phase 1→Phase 2 transition. Documented in CHANGELOG.md.
- **Schema versioning is a perpetual concern.** Each grammar
  extension (e.g., `Member[*]` for any-key glob) is a
  potential breaking change. Strict version-tagging at the
  file level (`version = 1`) plus engine-side compatibility
  layers when the schema bumps.
- **Token grammar is a small surface, but distinct from
  CodeQL's and Semgrep's.** Users coming from those tools
  need to learn the Stryx variant. Mitigated by the grammar
  being a near-direct rendering — translation guides for
  CodeQL and Semgrep formats live in
  `docs/summaries/migration.md`.

### Neutral

- **Public-rule API unchanged.** Rules consume summaries via
  the existing `ProjectIndex::resolve_summary` contract.
- **Cross-file taint contract (ADR 0003) unaffected.**
  External summaries are just more entries in
  `ProjectIndex`.
- **Convergence model (ADR 0004) unchanged.** Loaded once at
  startup; no fix-point participation.
- **Distribution unchanged.** Vendored summaries ship in the
  binary; no new install steps.

## Notes

### Why TOML, not YAML

- Already a project file (`Cargo.toml`); `stryx.toml` already
  exists for tsconfig-style settings.
- Stricter syntax than YAML (no whitespace ambiguity, no
  multiple-tag interpretations).
- `toml` crate is fast, deterministic, and small.
- `serde + toml` integration means the loader is ~50 LOC.

### Why a token grammar, not free-form Rust closures

- Determinism: a closure-based summary couldn't be cache-
  keyed without serialising the closure body.
- Distribution: closures are Rust-only; community
  contributions need a non-Rust path.
- Inspection: a TOML summary is human-readable in the failing
  finding's `--why` output. A closure is opaque.

### Why bundled defaults, not lazy fetch

- `--no-llm` and offline scans must work. Lazy fetch over
  network on first scan breaks the offline contract.
- Reproducibility: a CI scan two months apart should produce
  the same findings. Network fetches don't guarantee that.
- Trust: bundled summaries go through the project's review
  process; lazy fetches don't.

### OSS validation criterion

Slice 10.4 (vendored starter pack) is the first behavioural
slice. Expected diff: findings on real-world Next.js +
axios/zod/prisma codebases gain precision. The pass criterion:
- Every disappeared finding (sanitisation modelled) is verified
  by hand to be a true sanitisation.
- Every new finding (sink modelled) is verified to be an
  unmodelled-before sink we genuinely should have flagged.
- Net finding count change is documented per fixture.

### Reversibility

Each slice reverts cleanly:

- 10.1 — delete the parser; no consumer depended on it.
- 10.2 — delete the types and loader; substrate-only revert.
- 10.3 — flip `cfg(feature = "external_summaries")` off;
  `resolve_summary` uses pre-10.3 fallback.
- 10.4 — empty the vendored data directory; `external_summaries`
  loads zero entries; behaviour reverts to v0.3.x.
- 10.5 — drop `summaries_digest` from cache key; cache
  invalidates once. Pre-10.5 cache entries become orphaned but
  harmless.
- 10.6 / 10.7 — drop the CLI flags; behaviour reverts to
  default loading.
- 10.8 — drop `--suggest-summaries`; LLM remains deterministic.

### Provenance and licensing

The `Argument[N].Member[foo]` token grammar is informed by
CodeQL's access-path string format (`Argument[N].Member[foo].
ReturnValue` from
`javascript/ql/lib/semmle/javascript/dataflow/internal/
FlowSummaryPrivate.qll`, MIT-licensed). No code is reused; the
grammar is reimplemented in TOML idiom for our types. Semgrep's
YAML rule schema (LGPL-2.1) is a contrast case; their schema
mixes rule logic and library models. We separate the two
deliberately.

The vendored starter pack contains summaries we author
ourselves against publicly-documented library APIs. We do not
copy summaries from CodeQL or Semgrep model packs. Per
`THIRD_PARTY_LICENSES.md`, no entry is required; we will document
the inspiration in `docs/summaries/grammar.md`.

### Relationship to ADR 0008

External summaries inject `StepKind` instances into the rule-
side registry. The substrate from ADR 0008 must land through
slice 8.5 (propagation migration) before this ADR's slice 10.3
can land cleanly. If ADR 0008 lags, slice 10.3 ships with a
parallel direct-injection path into the visitor that's removed
when ADR 0008 catches up.

### Relationship to ADR 0009

Schema-discriminant guards (slice 9.7) are a special case of
the `kind = "sanitised" + when = "..."` summary form. Once both
ADRs land, library authors can describe `safeParse`-shape
discriminants declaratively rather than relying on engine-
hardcoded recognition.

## References

- [ADR 0002](0002-hybrid-ast-llm-architecture.md) — Layer 3
  LLM escalation; slice 10.8 surfaces summaries as suggestions.
- [ADR 0003](0003-cross-file-and-taint-as-core.md) — cross-file
  taint as v0.1 core; external summaries are additional
  `ProjectIndex` entries.
- [ADR 0004](0004-two-pass-fixpoint-with-iteration-cap.md) —
  driver loop; summaries load once at startup, no fixpoint
  participation.
- [ADR 0005](0005-taint-aware-cache-keys.md) — cache key
  contract; `summaries_digest` extends the key.
- [ADR 0006](0006-shape-lattice-taint-summary.md) — shape
  lattice; the token grammar parses *into* `Cell` shapes.
- [ADR 0007](0007-return-shape-tracking.md) — return-shape
  tracking; `ReturnValue.Member[foo]` paths populate
  `return_shape`.
- [ADR 0008](0008-taint-step-trait-substrate.md) — step-trait
  substrate; external summaries register `StepKind` instances
  at load time.
- [ADR 0009](0009-guard-based-barriers.md) — guard barriers;
  schema-discriminant guards (slice 9.7) compose with summary
  `when` clauses.
- [`crates/stryx_index/src/lib.rs:222`](../../crates/stryx_index/src/lib.rs)
  — `resolve_summary`; the bare-specifier fallback lands at
  slice 10.3.
- [`crates/stryx_rules/src/flows/unvalidated_body_to_db.rs:1529`](../../crates/stryx_rules/src/flows/unvalidated_body_to_db.rs)
  — current zod/valibot/yup hardcoded sanitiser; migrates to
  `zod.toml` at slice 10.4.
- [`crates/stryx_rules/src/flows/unvalidated_body_to_db.rs:1633`](../../crates/stryx_rules/src/flows/unvalidated_body_to_db.rs)
  — current Prisma/Drizzle/TypeORM hardcoded sinks; migrate to
  vendored TOML at slice 10.4 (subset).
- CodeQL — `internal/FlowSummaryPrivate.qll`,
  `Customizing Library Models for JavaScript` (MIT). Token
  grammar inspiration.
- Semgrep — YAML rule pack schema (LGPL-2.1). Contrast case;
  their schema unifies rules and models.
