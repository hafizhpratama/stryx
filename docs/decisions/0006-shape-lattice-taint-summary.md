# ADR 0006 — Field-sensitive shape lattice for taint summaries

- **Date**: 2026-05-10
- **Status**: Proposed
- **Decider**: Hafizh Pratama
- **Supersedes**: none
- **Refines**: [ADR 0003](0003-cross-file-and-taint-as-core.md), [ADR 0004](0004-two-pass-fixpoint-with-iteration-cap.md), [ADR 0005](0005-taint-aware-cache-keys.md)

## Context

The v0.1 taint engine summarises each exported function with a
`ParamFlow` whose precision is *one boolean per parameter per
predicate* (`reaches_db_sink_unsanitized`, `propagates_to_return`):

```rust
pub struct ParamFlow {
    pub name: String,
    pub reaches_db_sink_unsanitized: bool,
    pub propagates_to_return: bool,
    pub sink_span: Option<Span>,
}
```

This is enough to ship the three v0.1 flow rules — and intentionally
so. ADR 0003 picked this lattice because it bounds summary size by
parameter count and converges in a small number of fixpoint passes.

OSS validation against open-source Next.js and Hono codebases
exposed the precision ceiling of this design. Three classes of false
positive recur, all rooted in the same coarseness:

### Problem 1: whole-arg granularity collapses field-level safety

A handler that does

```ts
const { id } = z.parse(req.body);
await prisma.user.update({ where: { id }, data: { ...rest } });
```

is treated identically to one that does

```ts
await prisma.user.update({ data: req.body });
```

Both have `reaches_db_sink_unsanitized = true` for the parameter
carrying `req.body`. The first is safe (`req.body.id` was validated;
`...rest` is the FP-prone part the user actually owns); the second
is not. We currently rely on the where-clause severity downgrade
(slice 2 v3) to soften the FP — but the underlying summary still
loses the information that *only one field* of the body flowed.

### Problem 2: polymorphic helpers lose call-site context

A helper like

```ts
export function pickField<T extends keyof Body>(b: Body, k: T) {
  return b[k];
}
```

is summarised once per export. The current summary cannot say
"parameter `b`'s offset `.k` flows to return" — only "parameter `b`
flows to return." Every caller of `pickField` then conservatively
treats the whole returned value as carrying every part of `b`. This
is the single largest cross-file FP source we observed in the OSS
runs.

### Problem 3: HOF-shaped wrappers need a separate code path

`flow/auth-bypass-via-wrapper` reasons about callable arguments
(`withAuth(handler)`) by name-matching wrapper identifiers
against a hardcoded regex. Adding a new wrapper shape means editing
the rule. There is no general lattice element for "this parameter
is a function, and here is what flows through it."

The architectural question: stay on the boolean lattice and add
narrow side channels per FP class (the path we are on), or commit
to a structured lattice that subsumes the side channels and gives
us field-, polymorphic-, and HOF-sensitivity in one model?

## Options considered

### Option A — Stay on boolean ParamFlow; add side channels per FP class

Continue the slice 2 / slice 3 trajectory: each new precision ask
becomes another bool on `ParamFlow` (`where_only_taint`,
`return_field_subset`, …) plus rule-side suppression logic.

**Pros:**
- No engine rewrite.
- Each fix is a small, mergeable change.
- Cache keys (ADR 0005) remain stable; existing entries stay valid.

**Cons:**
- Flat-bool growth has a hard ceiling: cross-products of bools do
  not compose. "Only `.id` flows, but only into a where clause, but
  only when called from a wrapper that validated something else"
  is unrepresentable without a combinatorial bool count.
- Each new bool is a separate code path in every consumer rule.
- Polymorphic helpers (Problem 2) cannot be solved by adding bools;
  the missing primitive is *which offset* of the param flows where.
- Doubles down on a model we already know is too coarse for the
  patterns we've committed to catching.

Rejected.

### Option B — Adopt a Semgrep-style field-sensitive shape lattice

Replace `ParamFlow`'s booleans with a *shape* — a tree of cells
indexed by field/index offsets, with explicit clean/tainted
markers per cell, polymorphic placeholders for parameters, and
function-shaped cells for HOFs.

The lattice is the one Iago Abal describes in Semgrep's
`Shape_and_sig.ml` (LGPL-2.1, design publicly documented in
source comments — algorithm is reproducible, code is not):

```
Shape ::= Bot                 -- "_|_" don't know / don't care
        | Obj(BTreeMap<Offset, Cell>)
        | Arg(ArgId)          -- polymorphic parameter placeholder
        | Fun(Signature)      -- HOF cell

Cell  ::= Cell { xtaint: Xtaint, shape: Shape }
Xtaint ::= None | Tainted(LabelSet) | Clean
```

with two invariants that bound lattice height and keep summaries
minimal:

1. If a cell's xtaint is `None`, its shape is non-`Bot` and
   transitively reaches a `Tainted` or `Clean` cell. (No
   "useless" `None`-on-`Bot` cells.)
2. If a cell's xtaint is `Clean`, its shape is `Bot`.

**Pros:**
- Subsumes all three FP classes in one model:
  - Problem 1 — field granularity is native: `req.body` is
    `Cell(None, Obj { id -> Cell(Clean, Bot); rest -> Cell(Tainted, ..) })`.
  - Problem 2 — polymorphic shape variables (`Arg`) let us
    summarise a helper once and instantiate per call site, so
    `pickField`'s return shape becomes a function of which field
    the caller asked for.
  - Problem 3 — `Fun` cells let us reason about wrapper-handler
    relationships as data flow rather than name-matching.
- Algorithm is publicly documented; we reproduce from design, not
  from code (we are Apache 2.0; Semgrep's OCaml is LGPL-2.1, so we
  don't read it for transcription, only for design verification —
  see Notes).
- Lattice height is bounded by the program's offset depth + label
  set, which is finite for any given source file. Termination
  argument is not weaker than the current bool lattice.
- Composes cleanly with the per-function summary contract from
  ADR 0003 — no change to the iterative extract→run pipeline.

**Cons:**
- Summaries are larger. Memory per summary grows from O(params) to
  O(params × tracked offsets). Bounded but not negligible.
- Cache key contract (ADR 0005) widens: `taint_summary` must
  include shape contents, so existing cache entries invalidate on
  rollout. One-time cost, no schema migration needed (ADR 0005's
  content-addressed scheme handles it automatically).
- Engine code that consumes summaries (every flow rule) needs a
  shape-aware reader API, even when the rule doesn't care about
  fields. We mitigate with a `Shape::is_tainted_anywhere()`
  shorthand for boolean-lattice-equivalent queries.
- Termination argument requires the two invariants above to be
  enforced as runtime checks during summary construction; current
  bool lattice has no such obligation.

### Option C — Adopt a pointer/alias analysis (WALA-style)

Build a points-to graph over the AST and run taint as reachability
in that graph.

**Pros:**
- Catches aliasing FPs/FNs that no shape lattice can handle
  (`let a = b; a.x = taint; sink(b.x)`).
- Industry-standard approach for Java; ports exist for JS (WALA
  via Rhino).

**Cons:**
- 10–100× the engineering cost of Option B. Andersen-style
  analysis needs class-hierarchy analysis, points-to constraint
  generation, and cycle resolution. Performance budget (ADR
  0001 / `ARCHITECTURE.md`) does not survive this.
- Most AI-generated Next.js handler code we target does not exhibit
  the aliasing patterns that justify the cost — it's
  declaration-and-immediate-use. Field sensitivity captures the
  precision wins; aliasing is a long tail.
- Conflicts with our "boring stack, scale later" instinct. This
  is the v3+ option, not v0.3.

Deferred. Reconsider if Option B's precision plateau is hit by
shape-insensitive aliasing in practice.

### Option D — Gradual migration: offset-list ParamFlow first, then full shapes

Ship Option B in two halves.

- **Phase 1 (v0.2.x):** extend `ParamFlow` from `bool` to
  `Vec<(Offset, bool)>`. Boolean lattice per offset. No `Cell`,
  no `Arg`, no `Fun`. Solves Problem 1 only.
- **Phase 2 (v0.3):** full shape lattice as described in Option B.

**Pros:**
- Each phase is independently shippable and benchmarkable.
- Phase 1 alone validates the "field granularity matters in
  practice" hypothesis on real codebases before we commit to the
  full lattice.
- Lower per-phase risk; each PR has a smaller blast radius on the
  rule library.

**Cons:**
- Phase 1's data shape is throw-away — Phase 2 replaces it
  entirely. Duplicated migration effort across rule consumers.
- Phase 1 leaves Problems 2 and 3 unaddressed; the v0.2.x window
  still ships the polymorphic-helper FP class.

## Decision

**Option D — gradual migration, with the full lattice as the v0.3
target.**

The phased approach is the right balance: Phase 1 ships in the v0.2
window with limited risk, validates the field-granularity
hypothesis on real OSS codebases, and unblocks the where-only
severity classification and the validated-field family of FPs.
Phase 2 in v0.3 lands the full lattice and absorbs polymorphic
helpers and HOFs as native lattice features.

Phase 1 throw-away cost is real but bounded — Phase 2's `Cell` and
`Arg` constructors are additive over Phase 1's offset list (an
offset list is the trivial shape `Cell(xtaint, Obj { off_i -> Cell(...) })`
without nested cells). The migration is a refactor, not a rewrite.

### Implementation requirements

**Phase 1 (v0.2.x):**

- `stryx_taint::ParamFlow` gains a `tainted_offsets: Vec<Offset>`
  field. The existing `reaches_db_sink_unsanitized: bool` becomes
  `Self::tainted_offsets.is_empty().not()` and is kept as a
  derived accessor for source compatibility.
- `Offset` is a new type in `stryx_taint`:
  `pub enum Offset { Field(SmolStr), Index(u32), Any }`. JS-style
  field/string-index unification (Semgrep's `Ofld == Ostr`) is
  enforced in `Offset::eq` for `.a` vs `["a"]`.
- Where-clause severity classification (currently in
  `flows::unvalidated_body_to_db::classify_db_sink_taint`) moves
  onto offset-aware queries: `body.where.id` having different
  severity from `body.data.field` becomes a property of the offset,
  not a per-rule helper.
- Cache key (ADR 0005) `taint_summary` serialisation includes
  the offset list. Existing cache entries invalidate on rollout
  (one-time cost, content-addressed; no schema migration).

**Phase 2 (v0.3):**

- Full lattice: `Shape::{Bot, Obj, Arg, Fun}` and
  `Cell { xtaint, shape }` lands in `stryx_taint`. The two
  minimality invariants are enforced in a `Cell::canonicalize`
  helper run after every summary mutation.
- `ParamFlow` is replaced by `ParamShape: Cell`. Phase 1's
  `tainted_offsets` becomes the `Obj` constructor of the new
  shape.
- Polymorphic shape variables (`Arg(ArgId)`) are introduced for
  parameter shapes in summary construction. `ArgId` is content-stable
  (parameter index + function id), so cache keys remain
  deterministic across runs.
- HOF support (`Fun(Signature)`) lands as a separate slice within
  v0.3 — strictly after data shapes are validated on the OSS
  fixture suite.
- Cache key contract widens again — second one-time invalidation.

### Out of scope

- **Aliasing / pointer analysis.** Option C is deferred. If
  aliasing FNs prove material in v0.3 OSS validation, reopen.
- **Region-based analysis.** The "TODO: We can attach region ids"
  note in Semgrep's `Shape_and_sig.ml` is a longer-term
  alias-analysis foundation. Out of scope until aliasing demand
  materialises.
- **Type-flow integration.** Phase 4 in the roadmap covers deeper
  `oxc_semantic` use; the shape lattice is independent of type
  inference and ships first.

## Consequences

### Positive

- The three FP classes above become representable in the lattice,
  not papered over in rule-side suppression.
- Polymorphic helpers (the largest cross-file FP source in OSS
  validation) are summarised correctly with one summary per export
  — no more conservative whole-value propagation.
- HOF wrappers stop requiring name-regex matching; the lattice
  represents the relationship structurally.
- Aligns Stryx with the precision frontier of the open-source
  static-analysis space (Semgrep's shape lattice is the best
  publicly documented field-sensitive design we surveyed; CodeQL's
  IFDS is more powerful but requires the QL/database infrastructure
  we explicitly chose against in ADR 0003).
- Each phase ships independently, with its own benchmark suite and
  OSS validation pass.

### Negative

- **Two cache invalidations** during the v0.2.x → v0.3 window. ADR
  0005's content-addressed scheme handles them automatically (no
  manual migration), but cold scans during rollout are slower.
- **Summary memory grows.** Bounded by tracked offsets per param;
  worst-case observed in OSS fixtures is ~12 offsets/param. Memory
  budget per summary remains in the kilobyte range, well below any
  pipeline-level budget in `ARCHITECTURE.md`.
- **Lattice invariants must be runtime-checked.** A bug in
  canonicalisation that leaves a `Clean` cell with a non-`Bot`
  shape silently violates termination. We mitigate with debug-mode
  assertions in `Cell::canonicalize` and a property test
  (`crates/stryx_taint/tests/lattice_invariants.rs`) that runs
  random shape mutations and asserts canonicalisation
  idempotency.
- **Rule-library churn.** Every flow rule that reads
  `ParamFlow::reaches_db_sink_unsanitized` needs an audit when
  `ParamShape` lands. We expect the change to be small (most rules
  just need `Shape::is_tainted_anywhere()`), but it is a
  workspace-wide refactor at Phase 2.

### Neutral

- The extract→run pipeline shape (ADR 0003) is unchanged.
- `MAX_ITER` and convergence-warning behaviour (current
  `stryx_cli::ConvergenceSignal`) carry over verbatim. Lattice
  height is still finite, and the fixpoint argument is unchanged.
- Layer 3 LLM escalation is unaffected. UncertainZones still emit
  the same span/source data; the shape lattice is an internal
  precision improvement, not a new public surface.

## Notes

### Provenance and licensing

The shape lattice design is taken from the publicly documented
algorithm in Semgrep's `src/tainting/Shape_and_sig.ml` (Iago Abal,
LGPL-2.1, comments lines 67–185). Stryx is Apache 2.0 and we do
not link, copy, or transcribe Semgrep's OCaml. We reproduce the
algorithmic shape from design comments — the same approach we use
for OWASP/CWE pattern references. The inspiration credit (Talpin
& Jouvelot, "Polymorphic type, region and effect inference") is
cited in Semgrep's source comments and is itself open
literature.

`THIRD_PARTY_LICENSES.md` does not need an entry — there is no
code dependency, only an algorithmic-design reference.

### Termination argument (Phase 2)

The lattice has finite height for any given input program:

- `Bot` < `Cell(None, Obj _)` < `Cell(Tainted/Clean, _)`.
- `Obj` is a `BTreeMap<Offset, Cell>` over a finite offset set
  (offsets appearing in the source program plus `Any`).
- `Arg` is bounded by parameter count.
- `Fun` is bounded by the set of summarisable signatures, itself
  finite per program.

The two minimality invariants ensure no chain of `Cell(None, ...)`
extensions can grow without reaching a `Tainted`/`Clean` leaf.
Combined with the bounded-iteration cap from `stryx_cli` (currently
`MAX_ITER = 10`), termination is guaranteed and the convergence
warning surface is unchanged.

### Migration test plan

Phase 1 lands behind a feature flag (`STRYX_OFFSET_PARAMFLOW=1`)
for one minor release. The OSS validation suite (currently the
vercel/examples + selected Hono fixtures) is run with both
old and new ParamFlow; FP/FN deltas are reviewed before flag
removal.

Phase 2 follows the same pattern (`STRYX_SHAPE_LATTICE=1`). Both
flags are removed in v0.3 final.

### Reversibility

Phase 1 is fully reversible — `tainted_offsets` collapses to the
boolean by `Vec::is_empty()`. Phase 2 is reversible to Phase 1 by
collapsing `Shape::Obj` to its set of tainted offsets. Reversing
to v0.1 booleans is also possible but would be a deliberate
precision regression.

## References

- [ADR 0003](0003-cross-file-and-taint-as-core.md) — cross-file
  taint as v0.1 core; extract→run pipeline contract.
- [ADR 0004](0004-two-pass-fixpoint-with-iteration-cap.md) —
  driver loop; the shape lattice composes with the existing
  extract→run pipeline unchanged.
- [ADR 0005](0005-taint-aware-cache-keys.md) — cache key
  contract; shape contents enter the `taint_summary` field.
- [`docs/architecture/taint-engine.md`](../architecture/taint-engine.md)
  — engine design; needs update at each phase.
- [`crates/stryx_taint/README.md`](../../crates/stryx_taint/README.md)
  — vocabulary; needs update at each phase.
- Iago Abal, *"Shape_and_sig.ml"* design comments, Semgrep
  (LGPL-2.1, public source). Algorithmic inspiration only.
- J.-P. Talpin and P. Jouvelot, *"Polymorphic type, region and
  effect inference"*, J. Functional Programming, 1992. Cited by
  Semgrep as the polymorphic-shape inspiration; relevant for the
  `Arg` constructor.
