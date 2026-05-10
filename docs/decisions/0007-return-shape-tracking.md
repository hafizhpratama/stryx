# ADR 0007 — Return-shape tracking for cross-file precision

- **Date**: 2026-05-10
- **Status**: Proposed
- **Decider**: Hafizh Pratama
- **Supersedes**: none
- **Refines**: [ADR 0003](0003-cross-file-and-taint-as-core.md), [ADR 0006](0006-shape-lattice-taint-summary.md)

## Context

Phase 2 of [ADR 0006](0006-shape-lattice-taint-summary.md) shipped
the field-sensitive shape lattice (`Cell { Xtaint, Shape }` with
`Bot`, `Obj`, `Arg`) and the substrate to track "what shape of the
parameter flowed to a sink." `param_shape` is the single source of
truth for that question.

What v0.2.x cannot answer is **what shape of value the function
returns**. Today the engine summarises return-flow with a single
boolean:

```rust
pub struct ParamFlow {
    pub propagates_to_return: bool,
    // ...
}
```

True iff the param's value flows to the function's return. The
caller treats the call result as either "fully tainted" (whatever
the param was) or "fully clean" — no field granularity.

This is the precision ceiling of v0.2.x. Three patterns hit it:

### Problem 1: polymorphic field selectors

```ts
export function pickField<T extends keyof Body>(b: Body, k: T) {
  return b[k];
}

// caller
const id = pickField(body, "id");
await prisma.user.delete({ where: { id } });
```

`pickField` propagates `b` to its return. Today's summary says
`propagates_to_return = true`, so the caller's `id` is fully
tainted with whatever `body` carries. The caller's lookup at `where:
{ id }` fires at Medium (where-only severity downgrade) — but the
caller has actually only consumed `body.id`, not whole body. The FP
class is unrepresentable without return-shape tracking.

This is the case Iago Abal's Semgrep design comments call out as a
TODO for `Arg` polymorphism: *"Generalize to 'Taint.lval', e.g.
`function test(o) { return o.x }`."* — they had the type but not
the application.

### Problem 2: extract-and-pass helpers

```ts
export function shaped(body: any) {
  return { id: body.id, payload: body.data };
}

// caller
const out = shaped(body);
await prisma.user.update({ data: out.payload });
```

The helper maps caller-input to a structured return. The caller's
`out` carries `Obj { id: Tainted, payload: Tainted }` — knowable
from the helper's body — but Stryx today loses that structure. Any
read on `out.X` is treated as "fully tainted" because `out` came
from a propagating function.

### Problem 3: HOF-shaped wrappers as data

```ts
export function withAuth<H extends (req: Req) => Promise<R>>(handler: H): H {
  return (async (req) => {
    if (!await auth(req)) throw new Error("401");
    return handler(req);
  }) as H;
}

// caller
export default withAuth(async (req) => {
  const body = await req.json();
  await prisma.user.create({ data: body });
});
```

`flow/auth-bypass-via-wrapper` reasons about wrappers by name-
matching against a hardcoded regex. The substrate that would let
us reason structurally — *"this wrapper takes a function-shaped
arg, returns a function-shaped value, and the wrapper's body
demonstrably calls an auth helper before invoking its arg"* —
requires both `Shape::Fun(Signature)` (slice 2.4 of ADR 0006,
deferred) and return-shape tracking (this ADR). Each alone is
insufficient.

## Architectural question

Phase 3 design choice — how do we extend per-function summaries
to capture "what shape comes out?" Three options:

1. **Return-shape tracking with `Arg` instantiation** — the
   approach this ADR proposes.
2. **Inline expansion** — no summaries; visit callees in-place at
   each call site.
3. **Type-flow analysis** — use TypeScript's type information to
   infer return shapes.

## Options considered

### Option A — Return-shape tracking (chosen)

Extend `ExportedFunctionSummary` with a `return_shape: Option<Cell>`
field that records the canonical shape of the function's return
value. The visitor accumulates observations from `return <expr>;`
statements during the per-param simulation, just like it
accumulates observations from sink-call args today.

The lattice operations from ADR 0006 carry over directly:

- `return_shape_seen: Cell` on `FlowVisitor`, mirroring
  `param_shape_seen`.
- For each `Statement::ReturnStatement`, walk the argument
  expression and `merge_into` the discovered taint observations.
- At summary time, `canonicalize` the accumulated shape; emit `None`
  if no return statement carries taint, `Some(canonical)`
  otherwise.

`Shape::Arg` becomes meaningful: `pickField`'s return-shape
observations record `Arg(pickField, 0)` overlaid with the offset
chain `[k]`. At call sites, `Cell::strip_arg_for` (slice 2.3b's
deferred consumer wiring) and a new `Cell::instantiate_arg(
arg_id, replacement)` primitive replace `Arg(pickField, 0)` with
the caller's shape for the matching argument.

**Pros:**

- Reuses every Phase 2 substrate primitive verbatim. `merge_into`,
  `canonicalize`, `count_tainted_leaves`, `top_tainted_offsets`
  all work unchanged on return shapes.
- Solves all three precision problems (1, 2, 3) in one model. The
  `Fun` HOF variant from ADR 0006's slice 2.4 fits naturally into
  this design — a callable's "return shape" is just another shape.
- Composes with the existing fix-point driver (ADR 0004): adding
  `return_shape` as a sixth `ConvergenceSignal` axis (count of
  Tainted leaves in return shapes) is mechanical.
- Aligns with Semgrep's published design intent (their `Arg`
  comment explicitly anticipates this generalisation).
- Keeps the bounded-iteration soundness story (ADR 0004) — the
  monotone summary fixpoint still terminates because the lattice
  height is finite.

**Cons:**

- Summary memory grows again. `param_shape` already adds a tree
  per param; `return_shape` adds one more tree per function. OSS
  observation in v0.2.x: most summaries had ≤ 2 tracked offsets
  per param, average tree size in the kilobyte range. Doubling
  this is acceptable.
- Cache key contract widens (per ADR 0005). Existing v0.2.x cache
  entries invalidate on rollout. Same one-time-cost story as Phase
  1 → Phase 2; ADR 0005's content-addressed scheme handles it.
- `Cell::instantiate_arg(arg_id, replacement)` is non-trivial. The
  primitive must walk the cell tree and replace any matching `Arg`
  with `replacement`'s subtree, recursing into `Obj` cells along
  the way. Lattice-correct but adds a new primitive to the
  substrate.
- Determinism: summary serialisation order must remain stable
  (cache-key contract). The shape-lattice's `BTreeMap<Offset,
  Cell>` key ordering already handles this for `param_shape`;
  `return_shape` uses the same.
- `legacy propagates_to_return: bool` becomes derived (slice 2.5-
  style collapse) — `!return_shape.is_none() && return_shape's
  Tainted leaves are non-empty`. Same kept-for-cache-compat dance
  as the legacy fields on `ParamFlow`.

### Option B — Inline expansion

Drop the per-function summary contract; at each call site, visit
the callee's body inline as if it were inlined at the call. No
summary, no fixpoint.

**Pros:**

- Trivially solves precision: full path-sensitive analysis at every
  call site, with the caller's actual arg shapes already substituted.
- No summary serialisation, no cache key concerns.

**Cons:**

- Computational cost is exponential in the call depth. A
  controller → service → repository chain visits the repository's
  body once per controller-level call, including from unrelated
  controllers in the same project. The 30s/10k-file budget from
  `ARCHITECTURE.md` doesn't survive.
- Loses the deterministic-parallelism story (ADR 0004): inline
  expansion means no clean per-file parallel pass.
- Conflicts with the entire summary-fixpoint architecture (ADR
  0003). This is a v0 redesign, not a v0.3 evolution.

Rejected. Reconsider only if return-shape tracking is shown to be
fundamentally insufficient.

### Option C — Type-flow analysis

Use TypeScript's type information (via `oxc_semantic`'s alpha-stage
type-aware features, or by depending on the TypeScript compiler's
type checker) to infer return shapes from declared function types.

**Pros:**

- Free precision wherever types are well-annotated.
- Aligns with Phase 4 of the roadmap (deeper `oxc_semantic` use).

**Cons:**

- TypeScript types are *intent*, not *evidence*. A function declared
  `function foo(b: any): any` carries no type-shape information,
  but its body might still record clear taint flow. Type-flow
  alone misses these.
- `oxc_semantic` type-aware analysis is alpha. Not a v0.3 dependency.
- Doesn't capture function-internal observations (the `pickField`
  case's `b[k]` access is type-erased to `any`).
- Type-flow and return-shape tracking are complementary, not
  alternatives. We can adopt both — types as additional input to
  the lattice — once `oxc_semantic` matures.

Deferred to Phase 4. Return-shape tracking is independent and
should not block on type analysis.

### Option D — Phase 2 status quo, no Phase 3

Leave `propagates_to_return: bool` alone, accept the precision
ceiling, focus Phase 3 effort elsewhere (more rules, framework
breadth, LLM escalation hardening).

**Pros:**

- Cheapest by far. Zero engine work.
- Forces investment into rule-library breadth before depth.

**Cons:**

- Locks in the FP class above. `pickField`/`shaped`/wrapper
  patterns continue to either over-report (caller's whole-value
  taint) or get force-suppressed via per-rule heuristics that
  accumulate as code rot.
- `Shape::Arg` (already shipped in v0.2.x) becomes near-permanent
  dead substrate — it has no production consumer without return-
  shape tracking.
- Pushes the FP fight back to LLM escalation, which is bounded by
  cache hit rates and per-call cost.

Rejected. The substrate investment of Phase 2 is wasted without
this slice.

## Decision

**Option A — return-shape tracking with `Arg` instantiation** is
the v0.3 core.

The migration follows the same incremental pattern as ADR 0006,
each slice independently shippable and OSS-validated:

### Implementation requirements

**Slice 3.1 — visitor records return shape (substrate, observation-only):**

- `FlowVisitor.return_shape_seen: Cell`, fresh per per-param
  simulation. Initialised to `Cell::bot()`.
- `Statement::ReturnStatement` handling extends from the current
  "set tainted_return = true" to also call a new helper
  `record_taint_in_return(expr)` mirroring `record_taint_in_arg`
  but operating on the return-shape tree.
- Drained via `Cell::canonicalize` at summary time.

**Slice 3.2 — `ExportedFunctionSummary.return_shape: Option<Cell>`:**

- New field, `#[serde(default)]` for cache rollover compat.
- Populated in `build_summary` from the visitor's accumulated tree.
- `propagates_to_return: bool` continues to ship; v0.3.x can derive
  it from the shape (slice 2.5-style collapse) once consumers
  migrate.

**Slice 3.3 — `ConvergenceSignal::return_leaf_total`:**

- Sixth axis on the fix-point tuple, mirrors `tainted_leaf_total`
  but counts Tainted leaves in `return_shape`.
- Per-axis contract test in `stryx_cli::tests` per ADR 0004.

**Slice 3.4 — `Cell::instantiate_arg(arg_id, replacement)`
primitive:**

- New method that recursively replaces `Shape::Arg(id)` cells
  matching `arg_id` with the cell tree from `replacement`, merging
  into existing taint where applicable.
- Reuses `Cell::merge_into` for the substitution semantics.
- Documented with the same "wiring deferred" pattern as
  `strip_arg_for`; consumer-side wiring lands in slice 3.5.

**Slice 3.5 — first consumer: cross-file return-shape propagation
in `flow/unvalidated-body-to-db`:**

- At call expressions appearing on the right-hand side of a
  variable binding (`const x = helper(arg)`), look up
  `helper`'s `return_shape`.
- Instantiate `Arg(helper, idx)` references with the caller's
  shape for the corresponding `arg`.
- Merge the instantiated return shape into the caller's local
  binding's tracked shape.
- Existing finding logic (sink reads via `record_taint_in_arg`)
  picks up the more-precise shape automatically.

**Slice 3.6 — `Shape::Fun(Signature)` HOF (was ADR 0006 slice 2.4):**

- `Signature` carries the function's parameter shapes and return
  shape, anchored to the function's stable `fn_id`.
- Producer: when summarising a function whose return is itself a
  function-typed value (lambda, callable, named callee passed as
  result), record `Shape::Fun(Signature{...})`.
- Consumer: `flow/auth-bypass-via-wrapper` consumes `Fun` shapes
  to reason about wrapper composition structurally instead of by
  name-matching.

**Slice 3.7 — collapse `propagates_to_return: bool` per slice 2.5:**

- Field stays for serde/cache compat; populated from
  `return_shape.is_some_and(Cell::has_tainted_leaf)`.
- Visitor's `tainted_return` field retired (return shape is the
  source of truth).

### Out of scope

- **Type-flow integration** — Option C. Defer to Phase 4.
- **Inline expansion fallback** — Option B. Reconsider only if
  Phase 3 hits a fundamental precision ceiling.
- **Full call-site context-sensitivity** — at each call site, the
  caller passes specific shapes; return-shape tracking instantiates
  `Arg` with those, but the resulting shape is then merged into a
  per-param tree shared across all call sites in the caller's
  function. We don't track per-call-site distinct shapes. If two
  callers of `pickField` pass `body.id` and `body.email`, the
  caller's shape merges both; the result is `Obj{id, email}` not
  two separate per-call shapes. This is intentional — full
  context-sensitivity is exponential and not needed for the
  precision targets above.

## Consequences

### Positive

- The three precision problems above become representable in the
  lattice. `pickField` returns `Arg(pickField, 0)[k]`; the caller
  consuming `pickField(body, "id")` materialises `body.id`
  specifically, not whole `body`.
- `Shape::Arg` stops being dead substrate. The polymorphic
  placeholder finally has a producer (slice 2.3a) AND a consumer
  (slice 3.5). The Phase 2 type investment pays off.
- `flow/auth-bypass-via-wrapper` gets a structural foundation
  (slice 3.6 with `Fun` shapes) rather than a name regex.
- Composes cleanly with the existing fix-point driver and cache
  contract. No architectural surgery.
- Each slice is independently shippable, OSS-validatable, and
  reversible.

### Negative

- **Memory growth.** Summaries roughly double in size (one shape
  tree per param plus one per function return). Bounded by the
  same offset-set finiteness argument as Phase 2.
- **Cache invalidation.** One-time, content-addressed (no migration).
- **More lattice primitives to maintain.** `instantiate_arg`,
  `Fun` shape support, return-shape merge during cross-file
  propagation. Each is a few hundred lines of substrate plus tests.
- **Complexity for users reading summaries.** A debug dump of a
  `ProjectIndex` is denser. Not user-facing in normal operation.
- **Property-test surface grows.** Each new primitive needs
  idempotency, monotonicity, and lattice-soundness tests.

### Neutral

- Public API for rule authors is unchanged at this phase. Rules
  consume `param_shape` and (new) `return_shape` through the same
  helper methods (`has_tainted_leaf`, `top_tainted_offsets`, etc).
- Layer 3 LLM escalation (ADR 0002) is unaffected. Return-shape
  tracking is a deterministic precision improvement.
- The two-pass extract→run pipeline (ADR 0004) is unchanged.

## Notes

### Termination argument (slice 3.1+)

Adding `return_shape` doesn't change the lattice height beyond
what ADR 0006 already established. The shape lattice has finite
height for any program (offset set is finite, label set is
finite, `Arg` is bounded by parameter count). Iteration cap from
ADR 0004 (`MAX_ITER = 10`) carries over verbatim.

The new wrinkle: `instantiate_arg` could in principle introduce
non-monotonicity if it replaces an `Arg` placeholder with a more
specific shape — but the *result* shape is no smaller than the
input shape under the lattice ordering (concrete > Arg > Bot per
slice 2.3's `merge_into` semantics). The fixpoint argument holds.

### Slice 3.1 OSS validation criterion

OSS scan output should remain byte-identical to v0.2.x on existing
fixtures. Slice 3.1 is observation-only (no consumer reads
`return_shape`). The first behavioural change happens at slice
3.5; that's where finding-level diff is expected.

### Determinism for cache stability

The same per-`BTreeMap<Offset, Cell>` ordering that keeps
`param_shape` cache-stable applies to `return_shape`. Plus,
`Arg` ids are content-stable (function name + parameter index)
per slice 2.3. So:

```
return_shape serialisation =
    canonicalize(observed return shape) =
    canonicalize(merge of all return-stmt observations)
```

Order of return-statement processing matters — but the visitor
walks statements deterministically (file order), and merge is
commutative, so the result is the same byte-for-byte across runs.

### Reversibility

Each slice is reversible:

- 3.1 — drop the `return_shape_seen` field; `tainted_return` bool
  resumes as the source of truth.
- 3.2 — drop the field from `ExportedFunctionSummary`; serde's
  default-on-deserialize keeps old summaries valid.
- 3.3 — drop the new convergence axis; loop converges via existing
  five.
- 3.4 — drop `instantiate_arg`; no consumer depended on it pre-3.5.
- 3.5 — drop the consumer wiring; falls back to the v0.2.x
  `propagates_to_return: bool` path.
- 3.6 — drop `Fun` shape support; `flow/auth-bypass-via-wrapper`
  resumes name-regex matching.
- 3.7 — un-collapse `propagates_to_return`; keep both fields.

### Provenance and licensing

The return-shape design generalises Iago Abal's `Arg` polymorphism
sketch from Semgrep's `Shape_and_sig.ml` (LGPL-2.1, public source).
The TODO comment that anticipates this generalisation is the
inspiration; we do not reuse Semgrep code. As with ADR 0006, this
is an algorithmic-design reference; `THIRD_PARTY_LICENSES.md` does
not need an entry.

## References

- [ADR 0003](0003-cross-file-and-taint-as-core.md) — cross-file
  taint as v0.1 core; per-function summary contract.
- [ADR 0004](0004-two-pass-fixpoint-with-iteration-cap.md) —
  driver loop; new convergence axis composes unchanged.
- [ADR 0005](0005-taint-aware-cache-keys.md) — cache key contract;
  `return_shape` enters the `taint_summary` field.
- [ADR 0006](0006-shape-lattice-taint-summary.md) — shape lattice
  substrate; this ADR consumes it for return shapes.
- [`docs/architecture/taint-engine.md`](../architecture/taint-engine.md)
  — engine design; needs update at slices 3.2 and 3.5.
- [`crates/stryx_taint/README.md`](../../crates/stryx_taint/README.md)
  — vocabulary; updated at slice 3.2.
- Iago Abal, *"Shape_and_sig.ml"* design comments — Semgrep
  (LGPL-2.1). The `Arg` polymorphism TODO comment is the design
  inspiration for return-shape tracking; algorithmic only, no
  code reuse.
