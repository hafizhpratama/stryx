# Taint Engine

How Stryx tracks untrusted data across files and decides whether it
reaches a dangerous sink unsanitized.

> Foundational reference. Read [ADR 0003](../decisions/0003-cross-file-and-taint-as-core.md)
> first for *why* taint analysis is v0.1 core.

## Implementation status (as of v0.2.1)

This document mixes shipped behaviour with design intent. The
following are **not yet implemented** and are flagged inline with
📋:

- The `Source` / `Sink` / `Sanitizer` trait surface below — by v0.2
  it consolidated into the `TaintStep` trait substrate
  ([ADR 0008](../decisions/0008-taint-step-trait-substrate.md))
  carried by 17 `StepKind` closed-enum variants. The free trait
  objects in this doc remain a teaching shape; real code dispatches
  through `StepKind`.
- On-disk SQLite summary cache at `~/.cache/stryx/summaries/` — not
  in `scan()`. Phase 3.
- SCC detection on the call graph — not implemented. The bounded
  iteration cap (`MAX_ITER = 10`) per
  [ADR 0004](../decisions/0004-two-pass-fixpoint-with-iteration-cap.md)
  is the current substitute.
- `UncertainZone` emission and Layer 3 LLM escalation — vocabulary
  exists in `stryx_core`; no v0.2.1 rule emits zones yet
  (`flow/auth-bypass-via-wrapper` is the planned first consumer).

What **is** built at v0.2.1: `ParamFlow` with five reach flags
(`reaches_db_sink_unsanitized`, `reaches_fetch_sink_unsanitized`,
`reaches_redirect_sink_unsanitized`, `reaches_sql_sink_unsanitized`,
`reaches_exec_sink_unsanitized`) plus the SSRF precision flag
`fetch_sink_path_pinned_only`; the per-file extract pass + iterative
project-index fixed-point; the cross-file `lookup_callee_summary`
resolution path; the shape-lattice fields (`tainted_offsets`,
`param_shape`, `return_shape`, `propagates_to_return`) per
[ADRs 0006 / 0007](../decisions/0006-shape-lattice-taint-summary.md)
in observation-only mode; and 11 rules across single-file and
cross-file scope (see [`docs/rules/`](../rules/) for the catalog).

## What it is and why it exists

Most security-relevant AI failures in TypeScript are **taint flow problems**:
untrusted data (a request body, an env var, a filesystem read) reaches a
dangerous operation (a database write, `child_process.exec`, a response
body) without an effective sanitizer along the way.

Single-file linters (oxlint, Biome, ESLint) cannot see flows that cross
files. A handler in `app/api/users/route.ts` that calls `createUser()`
exported from `lib/users.ts` is invisible to per-file analysis even when
the cross-file flow is the entire bug.

The taint engine lives in `crates/stryx_taint/`. It runs on the normalized
AST produced by `stryx_ast` and the project-level index produced by
`stryx_index`. It is invoked by Layer 2 rules that opt in via
`Rule::taint_signature()`.

When the engine cannot trace a flow with confidence, it emits an
`UncertainZone` and lets Layer 3 LLM escalation answer the residual
question. This is the LLM's primary architectural role.

## Core abstractions

> 📋 Design intent — the Source/Sink/Sanitizer trait surface below is
> not the v0.1 rule extension surface. v0.1 rules implement the
> `crate::Rule` trait directly and hand-roll their matchers. The
> trait split below is the planned refactor target for when the rule
> count makes the abstraction worth its weight.

Three traits, one label set, one shared context:

```rust
// As shipped at v0.2.1 — see crates/stryx_taint/src/lib.rs.
pub enum TaintLabel {
    UserInput,     // request body, query params, headers, form data, searchParams
    AuthSubject,   // verified session subject (auth-bypass + scope rules)
    Secret,        // env vars + hardcoded credential-shaped strings
    DbRow,         // data read from a DB query
    Any,           // sanitisers that clear every label simultaneously
}

pub trait Source: Send + Sync {
    fn id(&self) -> &'static str;
    fn produces(&self, node: &Node, ctx: &TaintContext) -> Option<TaintLabel>;
}

pub trait Sink: Send + Sync {
    fn id(&self) -> &'static str;
    fn consumes(&self, node: &Node, labels: &TaintSet, ctx: &TaintContext)
        -> Option<Violation>;
}

pub trait Sanitizer: Send + Sync {
    fn id(&self) -> &'static str;
    fn cleanses(&self, node: &Node, label: TaintLabel, ctx: &TaintContext) -> bool;
}
```

Implementations live in `crates/stryx_rules/src/{sources,sinks,sanitizers}/`,
organized by category (HTTP, database, filesystem, etc.) and by framework
adaptation underneath.

The `TaintContext` exposes:
- The project `SemanticIndex` for cross-file lookups
- A `TypeHint` system (best-effort, not full inference) for distinguishing
  `Request` from a plain object
- Configuration loaded from `stryx.toml` (custom sources, custom sanitizers)

## The label set

The shipped labels at v0.2.1 are `UserInput`, `AuthSubject`,
`Secret`, `DbRow`, and `Any`. Each maps to a class of violation
with its own sink rules:

| Label | Typical sources | Typical sinks | Typical sanitisers |
|---|---|---|---|
| `UserInput` | `req.json()` / `req.body` / `req.text()` / `searchParams.X` | DB writes (`flow/unvalidated-body-to-db`), raw SQL (`flow/sql-injection`), `child_process` (`flow/command-injection-via-exec`), `fetch` (`flow/ssrf-via-fetch`), redirect (`flow/redirect-open`), `fs.<m>` (`flow/path-traversal`), LLM prompts (`flow/prompt-injection`), `dangerouslySetInnerHTML` (`flow/xss-via-dangerously-set-inner-html`) | zod / valibot / ajv / joi / yup; DOMPurify / sanitize-html; URL host allow-list; class-validator DTOs (NestJS heuristic) |
| `Secret` | `process.env.X`, hardcoded credential-shaped strings | response bodies (`flow/secret-to-response`) | redaction helpers, allow-listed env vars |
| `AuthSubject` | session helpers, `getServerSession()` | DB queries that scope by subject | auth checks (also a source — duality is intentional; consumed by `flow/auth-bypass-via-wrapper`) |
| `DbRow` | DB read results | response bodies (when row contains sensitive fields) | field-level redaction |
| `Any` | — | — | used by sanitisers that clear every label simultaneously |

Adding a new label is an ADR-level change. The label set is the
engine's public contract; rules and configurations depend on
stable names. `UserId`, `FilesystemRead`, and `NetworkResponse`
labels from earlier drafts of this doc were never shipped —
the equivalents are covered by `UserInput` plus rule-specific
sink families.

## Propagation model

How taint moves through code:

| Construct | Behavior |
|---|---|
| `let x = source()` | `x` carries source's labels |
| `const { a, b } = source()` | `a` and `b` each carry the labels |
| `source().method()` | result carries labels unless `method` is a sanitizer |
| `await tainted` | unwraps `Promise<T>` but preserves labels on `T` |
| `f(tainted)` | result carries `f`'s declared or inferred taint signature |
| `if (cond) { x = a } else { x = b }` | `x` gets the union of labels from both branches |
| `tainted.foo` (static access) | result carries the labels |
| `tainted[name]` (dynamic access) | engine bails to LLM (see below) |
| `JSON.parse(tainted)` | preserves `UserInput`; not a sanitizer |
| `String(tainted)` | preserves labels (coercion is not validation) |

Propagation is **forward-only** within a function. We do not track
backward "where could this value have come from" — that's a separate
analysis (provenance), useful but more expensive, and out of scope for
v0.1.

## Inter-procedural flow

Cross-file flow is the engine's core analysis. Implementation:

### Function summaries

For each function `f(p1, p2, ..., pn)` we compute a summary:

```
summary(f) = {
  // For each parameter, what labels does the return value carry
  // assuming that parameter has each possible label
  return_taint_for_param: [
    p1: { UserInput -> {UserInput}, Secret -> {Secret}, ... },
    p2: { ... },
    ...
  ],
  // For each parameter, what sinks inside f does it reach unsanitized
  internal_sinks_for_param: [
    p1: [ {sink_id: "db.create", label: UserInput, span: ...}, ... ],
    p2: [ ... ],
    ...
  ],
  // Whether the function performs sanitization on each label
  sanitizes: [Label1, Label2, ...],
}
```

When a caller passes a tainted argument, we look up the callee's summary
and propagate consequences.

### Building summaries

Summaries are built lazily and cached. On first encounter of `f` during
analysis:

1. Look up `f` in the project index.
2. Re-parse `f`'s file (the arena was freed after index construction).
3. Walk `f`'s body in the engine's intra-procedural mode.
4. Compute the summary and store it keyed by `blake3(function_body_source)`.
5. Free the re-parsed arena.

Subsequent calls hit the cache.

📋 Design intent: an on-disk cache at `~/.cache/stryx/summaries/` for
repeat scans on the same machine. v0.0.1 keeps summaries in-memory
only.

### Cycles and recursion

Call graphs in real codebases have cycles (mutual recursion, framework
plugins, dependency injection patterns). v0.0.1 handles them with a
single mechanism:

- **Bounded iteration**: the engine runs the per-file extract pass
  for at most `MAX_ITER = 10` rounds (`crates/stryx_cli/src/lib.rs`),
  consulting the previous round's `ProjectIndex` each time. Pure
  recursion converges fine because the lattice is finite (two-element
  product over `(file, exported_fn, param_idx)`); mutual recursion
  through a cycle longer than 10 hops is silently under-approximated
  and is the chief soundness limitation users should be aware of.

📋 Design intent (Phase 2):

- **SCC detection** on the call graph using Tarjan's algorithm,
  iterating each SCC to its own fixed-point in topological order.
  Replaces the bounded-iteration cap with proper convergence.
- **`UncertainZone` emission** when a flow exits via the iteration
  cap without converging, escalating the residual question to Layer
  3 instead of silently dropping the finding.

### Across npm dependency boundaries

We do **not** propagate taint through `node_modules` in v0.1. Function
calls into installed packages are treated as opaque: input labels do not
propagate to the return value, and we trust the package's interface.
This is unsound in principle (a malicious package could leak inputs to a
sink internally) but tractable in practice. Supply-chain analysis is a
separate problem that warrants its own engine.

Configurable per-package overrides land in Phase 2:

```toml
[taint.packages."some-validator"]
treat_default_export_as = "sanitizer"
labels_cleansed = ["untrusted-input"]
```

## Soundness vs precision

We pick **precision over soundness**. This is a load-bearing decision.

A sound analysis reports every real flow but also many that aren't real;
users mute the tool. A precise analysis reports flows we are confident
about; users miss some real bugs but trust what they see.

Concrete consequences of choosing precision:

1. We bail to LLM on dynamic dispatch instead of conservatively assuming
   every callee is reachable.
2. We limit recursion depth instead of widening to fixed-point on every
   cycle.
3. We treat unknown function calls as taint-preserving but not
   taint-amplifying.
4. We do not flag "this *might* flow if reflection is used."

This stance is repeated in AGENTS.md and the rule template so contributors
align rules to it. A rule that requires soundness should be implemented
elsewhere (e.g., as an opt-in `--strict` mode in a future phase).

The LLM is the recall recovery path. When the engine bails, the
UncertainZone gets a concrete LLM question, not an open-ended "is this
safe?" prompt.

## Bail-out conditions

The engine emits an `UncertainZone` (and stops tracing) when it
encounters:

- **Dynamic property access**: `obj[computed]`, `obj[name]` where `name`
  isn't a literal
- **Dynamic dispatch**: `(map[name])(args)`, function values from arrays
- **Reflection**: `Reflect.*`, `Object.getOwnPropertyDescriptor`,
  `Object.defineProperty` on relevant objects
- **`eval`-shape**: `eval`, `Function()`, `vm.runIn*`
- **Native bindings or declarations only**: imports from `node:*` whose
  body we can't see, ambient declarations
- **Recursion or call-graph cycle past depth 3**
- **Anonymous functions stored in mutable bindings** that we can't
  conservatively associate with a single body
- **Spread into unknown callees**: `f(...args)` where `f` is dynamic

Each bail-out emits an UncertainZone with `reason: "taint propagation halted at <kind>"`.
Layer 3 receives the zone source, the labels involved, and a focused
prompt: "Given this code region, does taint label `UserInput`
reach sink `db.create` without an effective sanitizer?"

## LLM escalation interface

When the engine bails, it produces:

```rust
pub struct TaintUncertainZone {
    pub zone: Zone,                   // file + byte range
    pub source_summary: SourceSummary, // where the taint originated
    pub labels: TaintSet,             // what labels are live
    pub bail_reason: BailReason,      // why we stopped tracing
    pub candidate_sinks: Vec<SinkInfo>, // what we suspect we'd reach
}
```

The Layer 3 prompt is rendered from a template at
`crates/stryx_llm/prompts/taint/<bail_reason>.txt`. Each bail reason has
its own prompt because the question shape differs.

Example prompt for `dynamic-dispatch`:

```
You are analyzing a TypeScript code region for taint flow safety.

Source code:
{ZONE_SOURCE}

A static analyzer detected that an untrusted value (label: {LABELS})
flows into a dynamic dispatch site, after which static tracing cannot
continue. The static analyzer suspects the value may reach one of these
sinks: {CANDIDATE_SINKS}.

Question: Considering the dynamic dispatch and any sanitizers visible
in the region, does the untrusted value reach any of the candidate
sinks without an effective sanitizer?

Definitions:
- "Effective sanitizer" means a runtime check that constrains the
  value's shape and types, such as zod.parse, ajv.validate, or
  equivalent.
- TypeScript type assertions (`as User`) are NOT sanitizers.

Return JSON only:
{
  "reaches_sink": boolean,
  "sink_id": string | null,
  "sanitized_by": string | null,
  "confidence": number,
  "reasoning": string
}
```

Confidence threshold and caching follow [`llm-escalation.md`](llm-escalation.md).
The cache key is taint-aware:

```
blake3(zone_source + taint_summary + rule_id + prompt_hash + model_version)
```

Same syntactic zone in different taint contexts caches separately.
This is intentional — same code may be safe in one context and unsafe
in another.

## Performance

Targets, p99:

| Operation | Cold | Warm |
|---|---|---|
| Build function summary, single function | ≤ 2ms | cache hit ≤ 50µs |
| Whole-project taint pass, 100k LoC | ≤ 5s | ≤ 1s (cache-dominated) |
| Cross-file flow query | ≤ 100µs | ≤ 100µs |
| Memory: function summaries | ~100 bytes/function | n/a |

The function-summary cache is the load-bearing optimization. Without
it, re-analyzing every function on every scan is intractable on real
monorepos. 📋 In v0.0.1 the cache is in-memory only; an on-disk
cache at `~/.cache/stryx/summaries/` is planned for Phase 2.

CI fails if the warm whole-project taint pass on the standard 100k-LoC
fixture exceeds 1.5s.

## Adding a new source / sink / sanitizer

> 📋 The teaching-shape example below shows the v0.0.1 `Source`
> trait. At v0.2.1 the substrate consolidated into `TaintStep` +
> closed-enum `StepKind` per
> [ADR 0008](../decisions/0008-taint-step-trait-substrate.md) so
> rule visitors dispatch through one enum instead of trait-object
> vectors. The real shipped shape for `BodySource` lives at
> [`crates/stryx_rules/src/steps/sources/body.rs`](../../crates/stryx_rules/src/steps/sources/body.rs);
> sinks at `crates/stryx_rules/src/steps/sinks/`; sanitisers at
> `crates/stryx_rules/src/steps/sanitizers/`. Adding a step today
> means adding a `StepKind` variant in `steps/mod.rs` and wiring
> its `TaintStep` trait method dispatch.

The pattern, in legacy `Source`-trait form:

```rust
// crates/stryx_rules/src/sources/frameworks/nextjs.rs

use stryx_ast::nodes::*;
use stryx_taint::{Source, TaintContext, TaintLabel};

pub struct NextRequestBody;

impl Source for NextRequestBody {
    fn id(&self) -> &'static str {
        "nextjs/request-body"
    }

    fn produces(&self, node: &Node, ctx: &TaintContext) -> Option<TaintLabel> {
        let call = node.as_call_expression()?;
        let member = call.callee.as_member_expression()?;
        let method = member.property.name();

        if !matches!(method, "json" | "formData" | "text" | "arrayBuffer") {
            return None;
        }

        if !ctx.type_hint(&member.object).is_request_like() {
            return None;
        }

        Some(TaintLabel::UserInput)
    }
}
```

Each new source/sink/sanitizer needs:

1. The implementation file
2. A doc entry in `docs/architecture/taint-catalog.md`
3. A real-world fixture in `tests/fixtures/taint/<id>/` showing the
   source or sink firing on a minimal reproduction
4. A counter-fixture showing it correctly *not* firing
5. Registration in `crates/stryx_taint/src/registry.rs`

## Configuration

Users can extend the engine via `stryx.toml` for project-specific patterns:

```toml
[taint.sources]
"@/lib/db.queryRaw" = "untrusted-input"

[taint.sinks]
"@/lib/email.send" = { label = "secret", reason = "leaks in logs" }

[taint.sanitizers]
"@/lib/validate.body" = ["untrusted-input"]

[taint.packages."some-pkg"]
treat_export_as = "sanitizer"
labels_cleansed = ["untrusted-input"]
```

Project-level configuration is the primary extensibility mechanism for
v0.1. Custom Rust rules and WASM plugins are deferred (see ADR 0003).

## Failure modes

What happens when the engine encounters problems mid-scan:

- **Index entry missing for a callee**: the function may be re-exported
  through paths the index didn't capture. We bail at the call site with
  `bail_reason: "callee-not-resolved"` and let the LLM see the call
  chain. We log so we can tighten the index.
- **Re-parse fails**: if a file changed between index construction and
  summary construction, we log and treat the function as opaque. The
  scan completes; that one function is analyzed pessimistically.
- **Summary cache corruption**: detect via hash mismatch, clear, recompute.
  Never crash on cache.
- **Out-of-memory on a pathological repo**: graceful degradation. We
  spill less-recently-used summaries to disk before OOM and re-fetch on
  demand. We log the spill rate; high rates indicate infrastructure
  needs more headroom.

## Open questions

- **Public extensibility surface.** Should `Source`, `Sink`, `Sanitizer`
  be a public Rust API for community-authored taint extensions? Versioning
  the trait shape across releases is hard. Likely Phase 3.
- **Async function call modeling.** Current design unwraps `Promise<T>`
  labels at await sites. Complex Promise chains (`Promise.all`, racing
  patterns) need test fixtures and possibly bespoke handling.
- **Generic functions.** `function f<T>(x: T): T` with `T = TaintedRequest`
  — current design doesn't propagate taint through generic instantiation.
  Reasonable for v0.1, revisit when type-aware analysis lands.
- **TaintLabel arithmetic.** When a value carries both `UserInput`
  and `UserId`, which sinks fire? Current design: a sink registers
  interest per label; multiple labels mean multiple sink checks. Worth
  validating on real fixtures.

## See also

- [ADR 0003](../decisions/0003-cross-file-and-taint-as-core.md) — why
  taint analysis is core
- [`semantic-index.md`](semantic-index.md) — the project-level index
  that the taint engine queries
- [`cross-file-rules.md`](cross-file-rules.md) — when to use the index
  directly, when to use taint, when to escalate (forthcoming)
- [`llm-escalation.md`](llm-escalation.md) — Layer 3 mechanics
- [`rule-format.md`](rule-format.md) — the `Rule` trait and how rules
  declare taint signatures
- Semgrep Pro taint mode — reference for precision-first design
- CodeQL data-flow — reference for sound inter-procedural analysis
