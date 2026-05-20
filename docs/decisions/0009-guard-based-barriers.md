# ADR 0009 — Guard-based barriers

- **Date**: 2026-05-10
- **Status**: Proposed
- **Decider**: Hafizh Pratama
- **Supersedes**: none
- **Refines**: [ADR 0006](0006-shape-lattice-taint-summary.md), [ADR 0008](0008-taint-step-trait-substrate.md)

## Context

Stryx today recognises one shape of guard-based sanitisation:
**negative early-return narrowing**. The pattern is:

```ts
if (!ALLOWED_KEYS.includes(field)) return res.status(400).end();
await prisma.user.update({ where: { [field]: value } });
```

`flow/unvalidated-body-to-db` collects file-scoped `const` allow-lists
into `FlowVisitor.allow_lists`
(`crates/stryx_rules/src/flows/unvalidated_body_to_db.rs:115`); the
visitor's `Statement::IfStatement` arm
(`unvalidated_body_to_db.rs:442–462`) detects the negation pattern via
`collect_includes_narrowed` (line 1886) and, when the then-branch
returns, removes the narrowed name from the current scope. From that
point in the scope, `field` is treated as untainted.

This is real progress over no narrowing at all — it eliminates a
genuine FP class on Prisma `where: { [allowedKey]: ... }` patterns.
But four guard shapes that backend code routinely uses are still
invisible to the engine:

### Problem 1: positive branch-scoped narrowing

```ts
if (ALLOWED_KEYS.includes(field)) {
  await prisma.user.update({ where: { [field]: value } });
} else {
  return res.status(400).end();
}
```

The same membership test, swapped polarity, no early return — `field`
is provably in the allow-list inside the then-branch. Today the
visitor walks both branches with `field` still tainted. The finding
fires inside the if-branch where it shouldn't.

This is the single most common shape Cursor/Copilot emit when the
developer asks for "validate this is one of [...]" — the LLM picks
the positive structural form because it's the more natural English-
to-code mapping. Stryx's negative-only recognition catches the less-
common form.

### Problem 2: type-narrowing guards

```ts
const id = req.body.id;
if (typeof id !== "string") return res.status(400).end();
await prisma.user.findUnique({ where: { id } });
```

`typeof id !== "string"` is a TypeScript-idiomatic narrowing guard.
After the early return, `id` is provably a string — type confusion
attacks (passing a `{ $ne: null }` object) are ruled out. The
`flow/unvalidated-body-to-db` rule today fires Medium severity
(where-only) on this pattern despite the runtime check.

`secret_to_response.rs:556`'s `is_boolean_coercion` recogniser
already inspects similar shapes for a different purpose; the
substrate to walk these expressions exists. What's missing is the
*sanitisation* effect.

### Problem 3: schema-test guards

```ts
const parsed = userSchema.safeParse(req.body);
if (!parsed.success) return res.status(400).json(parsed.error);
await prisma.user.create({ data: parsed.data });
```

`safeParse` returns `{ success: boolean, data?: T, error?: ZodError }`.
The early-return guard on `!parsed.success` proves `parsed.data` is
the validated, schema-conformant payload past this point. Today the
sanitiser recogniser
(`unvalidated_body_to_db.rs:1529 is_sanitizer_call`) fires only on
the imperative `.parse(...)` form — `safeParse` plus the discriminant
check is unrecognised, and `parsed.data` reads as tainted.

### Problem 4: nullability guards

```ts
const userId = req.headers["x-user-id"];
if (!userId) return res.status(401).end();
await prisma.user.findUnique({ where: { id: userId } });
```

The truthiness check guarantees `userId` is non-empty past the
early return. Without it, `userId` could be `undefined` and Prisma
would behave undefined-but-not-blocked. The check itself isn't a
sanitiser in the taint sense — the value is still untrusted — but
several rules currently fire Medium-severity findings on this
pattern that aren't actionable: the auth flow has *some* check;
the question is whether it's a *value* check.

This is a softer case than 1–3 — the right output is "Low
severity, suggests adding a parser" not "no finding" — but the
substrate that recognises the guard is the same.

## Architectural question

How do we model "this taint is cleared in this branch only" without
building a full control-flow graph?

The competitive review (May 2026) flagged this as a clear
CodeQL-side win: their `BarrierGuards.qll` models a guard as a
`(node, polarity)` pair, with the QL evaluator handling the
control-flow propagation declaratively. Semgrep's approach is
more conservative — they model sanitisers as nodes in the dataflow
graph, not as branch-scoped overrides — and the Semgrep deep-dive
explicitly notes Semgrep doesn't handle Problem 1's positive
branch-scoped pattern cleanly either.

Stryx today operates without a CFG, leaning on the AST's natural
nesting. The opportunity is to extend the existing visitor pattern
with branch-scoped overrides via the scope stack we already have
(`scopes: Vec<HashMap<String, Cell>>`), rather than introduce a
CFG layer.

## Options considered

### Option A — Branch-scoped Clean overrides via the existing scope stack (chosen)

Push a fresh `HashMap<String, Cell>` onto `FlowVisitor.scopes` when
entering a branch protected by a recognised guard. In that scope,
write `Cell::clean()` overrides for the names the guard narrows.
The existing scope-walk lookup (`local_shape` at
`unvalidated_body_to_db.rs:202`) already walks parent scopes, so
the override naturally hides parent-scope taint for the duration of
the branch. Pop the scope on branch exit. Late-branch taint
re-entry (a name re-tainted inside the branch via assignment)
shadows the override correctly via the same scope-stack semantics.

Guard recognition lives in a closed-enum dispatch under
[ADR 0008](0008-taint-step-trait-substrate.md)'s step-trait
substrate:

```rust
pub enum GuardKind {
    MembershipPositive(MembershipGuard),  // ALLOWED.includes(x)
    MembershipNegative(MembershipGuard),  // !ALLOWED.includes(x)
    TypeofString(TypeofGuard),            // typeof x === "string"
    TypeofNotString(TypeofGuard),         // typeof x !== "string"
    SchemaSuccess(SchemaSuccessGuard),    // parsed.success === true
    SchemaFailure(SchemaSuccessGuard),    // !parsed.success
    Truthy(TruthyGuard),                  // if (x) { ... }
    Falsy(TruthyGuard),                   // if (!x) { ... }
}

pub struct GuardEffect {
    pub names: Vec<String>,    // narrowed names
    pub clears: bool,          // true → Clean override, false → no-op
    pub polarity: BranchPolarity, // Then or Else
}
```

The visitor's `Statement::IfStatement` arm evaluates
`recognise_guard(&is.test) → Option<GuardEffect>` once per
if-statement, then:

- if `effect.polarity == Then`, push a clean-override scope before
  walking `is.consequent`, pop after
- if `effect.polarity == Else`, push the override scope before
  walking `is.alternate`
- early-return narrowing (today's behaviour) becomes the special
  case where `branch_returns(&consequent)` is true and the override
  applies *to the rest of the enclosing scope*, not to a freshly-
  pushed branch scope. We mark the guard's narrowed names directly
  in the current scope as today.

Ternary expressions (`isValid(x) ? sink(x) : ""`) get the same
treatment via the visitor's `ConditionalExpression` walk — push a
scope around the consequent/alternate visit.

**Pros:**

- **Reuses substrate.** Scope stack already exists for slice 3.5's
  per-local shape tracking. Branch scopes are one more push/pop
  pair, no new data structures.
- **No CFG cost.** The AST's structural nesting is enough for the
  90% case (branch-scoped clears on if/else and ternaries). The
  early-return case is a special-case extension to the *enclosing*
  scope, which today's narrowing already does.
- **Composes with ADR 0008's step-trait registry.** `GuardKind`
  becomes a `StepKind` variant; recognisers ship in
  `crates/stryx_rules/src/steps/sanitisers/guards/`.
- **Shared across rules.** `MembershipGuard` is the same recogniser
  whether `flow/unvalidated-body-to-db` or `flow/log-injection`
  consumes it. Drift class closed.
- **Existing narrowing code becomes a special case.** The early-
  return path stays; what changes is that it's now driven by a
  recognised `GuardKind::MembershipNegative` rather than a hand-
  rolled `collect_includes_narrowed` call.
- **No surprise interactions with the fix-point.** Branch-scoped
  Clean overrides are local to one visitor pass; they don't enter
  function summaries (slice 9.4 below). No new convergence axis,
  no new monotonicity hazard.

**Cons:**

- **No path-sensitivity for inter-statement guards.** If the guard
  spans two statements (`if (cond) { x = clean; } else { x = dirty; }
  sink(x);`), the merge at the join point is unsound for either
  branch. Stryx today treats post-join `x` as the union of both
  branches' assignments — adding branch-scoped Clean overrides
  preserves that behaviour. Out of scope for this ADR; deferred to
  a hypothetical CFG-layer ADR.
- **Re-tainting inside a guarded branch needs care.** If
  `if (allowed.includes(x)) { x = req.body.evil; sink(x); }`, the
  override must be shadowed by the assignment, not the other way
  around. The scope-stack semantics already handle this — writes
  go to the topmost scope, and the override in that same scope
  gets overwritten — but the test surface needs to confirm.
- **Some guards are not branch-bound.** A standalone
  `assert(typeof id === "string");` on a CFG would clear `id`
  type-tag past the assert. Stryx's AST-only model can't see that
  without recognising assertion calls as one-sided guards. Slice
  9.5 below adds `assert*`-shape recognition; everything else is
  out of scope.
- **The catalogue grows.** Each new guard shape (e.g.
  `Number.isInteger(x)` for integer narrowing) is a new
  `GuardKind` variant. Acceptable — closed-enum addition, type-
  checked at the call site.

### Option B — Status quo: keep negative-early-return narrowing, expand the catalogue inline

Keep the hand-rolled `collect_includes_narrowed` and add new helpers
for `typeof` / `safeParse` / truthiness recognition. No scope-stack
generalisation; everything is early-return.

**Pros:**

- Cheapest. ~5–10 LOC per new guard shape.
- The narrowing behaviour we already ship doesn't change.
- No risk of branch-scope interaction bugs.

**Cons:**

- Doesn't solve Problem 1 (positive branch-scoped narrowing) at
  all. The pattern stays invisible to the engine. Per the
  competitive review this is the most common shape in real handlers.
- Each new shape duplicates the per-rule predicate problem ADR 0008
  is fixing.
- The hand-rolled recognisers (`collect_includes_narrowed`,
  `match_includes_negation`) are ~80 lines together and growing.
  Adding 4 more shapes brings them past 200 lines, all in one rule
  file.

Rejected. Treats the symptom (more shapes), not the architectural
gap (branch-scope semantics).

### Option C — Full control-flow graph layer

Build a CFG over the AST in `stryx_taint`; run the existing visitor
over CFG basic blocks rather than AST nodes. Guards become
predicates on edges, with merge points handling join-time taint
union.

**Pros:**

- Maximally precise. Inter-statement guards, post-join taint
  merging, loop-carried narrowing — all naturally expressible.
- The stylistic peer (CodeQL) operates this way. Path-sensitive
  results without per-rule visitor code.

**Cons:**

- **Substantial substrate cost.** A correct CFG for TypeScript
  including async/await, generators, try/catch/finally, labelled
  breaks, switch fall-through is a multi-KLOC project. CodeQL's
  CFG construction for JS is non-trivial code.
- **Performance question.** CFG construction adds a per-file pass.
  The 1ms-per-rule-per-file budget tightens.
- **Out of phase for v0.3.x.** Phase 4 of the roadmap (ADR 0003)
  contemplates type-aware analysis via deeper `oxc_semantic` use;
  CFG is a sibling concern that fits better in that phase.

Rejected for v0.3.x. The 90% case is reachable without CFG; the
remaining 10% is honest LLM-escalation territory until Phase 4.

### Option D — LLM escalation for guard-shape uncertainty

When the visitor sees an if-statement protecting a sink with a
guard it doesn't recognise, emit an `UncertainZone` for Layer 3
(LLM) verification. The LLM judges whether the guard is in fact a
sanitiser.

**Pros:**

- Catches arbitrary guard shapes including custom validators
  (`if (myValidate(x)) { ... }`).
- Bounded by Layer 3's existing cache contract (ADR 0005).

**Cons:**

- LLM escalation budget is finite and aspirational (cache hit
  rates not yet measured at production load).
- Doesn't address the structural patterns 1–4 above, which AST-
  level recognition catches deterministically. Spending LLM
  budget on cases the AST can decide is wasteful.
- LLM escalation needs the *substrate* of guard recognition to
  identify which zones to escalate. Without Option A, every if-
  statement near a sink becomes a candidate zone.

Adopted as a **complement, not a replacement.** Slice 9.6 below
emits an `UncertainZone` when the guard's structure looks like a
custom validator (call expression test, no `GuardKind` match).

## Decision

**Option A — branch-scoped Clean overrides via the existing scope
stack** is the v0.3.x guard-barrier substrate.

Migration follows the slice discipline of ADR 0006/0007/0008:
each slice independently shippable, byte-identical-on-failure
fallback, reversible.

### Implementation slices

**Slice 9.1 — `GuardKind` enum and `recognise_guard` substrate
(no consumer):**

- New module `crates/stryx_rules/src/steps/sanitisers/guards/`
  per ADR 0008's layout.
- `GuardKind` closed enum with the variants above.
- `recognise_guard(expr: &Expression) -> Option<GuardEffect>` —
  closed-enum dispatch over recognised shapes, returning the
  narrowed names and polarity.
- `MembershipGuard` consumes `FlowVisitor.allow_lists` (the
  hoisted-const allow-list collector stays).
- Shipped without consumers; OSS scan output remains byte-
  identical.

**Slice 9.2 — branch-scope mechanism on the visitor:**

- `FlowVisitor::push_branch_scope(narrowed: &[String])` and
  `pop_branch_scope()` helpers.
- `push_branch_scope` clones the current scope (or pushes a fresh
  one — TBD by perf bench) and writes `Cell::clean()` for each
  narrowed name.
- `pop_branch_scope` discards the top scope.
- No consumer yet; substrate-only. Tested via the unit-test surface
  on `local_shape` lookup correctness.

**Slice 9.3 — `IfStatement` consumer (positive + negative branch-
scoped narrowing):**

- The visitor's `Statement::IfStatement` arm calls
  `recognise_guard(&is.test)`.
- `Then`-polarity guards push a branch scope around `is.consequent`;
  `Else`-polarity guards push around `is.alternate`.
- The existing early-return narrowing path becomes the
  `branch_returns(&consequent)` special case, applied to the
  *enclosing* scope.
- Behaviour change: positive `if (allowed.includes(x)) sink(x)`
  stops firing. This is the first behavioural slice; expect finding-
  level diffs on the OSS sample.

**Slice 9.4 — `ConditionalExpression` consumer (ternary):**

- `isValid(x) ? sink(x) : default` — branch scope around the
  consequent; the alternate gets the `Else`-polarity scope.
- Smaller surface than `IfStatement`; mostly mirrors the
  IfStatement logic.

**Slice 9.5 — assert-shape one-sided guards:**

- `assert(typeof id === "string");` clears taint past the assert.
- Recognise `assert(cond)`, `invariant(cond, msg)`,
  `node:assert`'s function calls.
- Treated as an "early-return guard with no return statement" —
  the assert's *failure* is the one-sided narrowing point; success
  flows through with the cleared override applied to the enclosing
  scope.

**Slice 9.6 — `UncertainZone` emission for unrecognised guards:**

- When `recognise_guard` returns `None` but the if-test is a
  call expression *and* the if's body or alternate contains a
  sink-call, emit an `UncertainZone` over the call expression's
  span.
- Layer 3 (LLM) judges whether the call is in fact a validator.
- Zone cache key per ADR 0005.

**Slice 9.7 — schema-discriminant guard support:**

- Extends `SchemaSuccessGuard` recogniser to handle the
  `safeParse` + `parsed.success` + `parsed.data`/`parsed.error`
  property-narrowing chain.
- Touches return-shape tracking (ADR 0007) — the override clears
  taint on `parsed.data` specifically, not the full `parsed`
  object.
- Lands after slice 9.3's behavioural baseline is validated on OSS.

### Out of scope

- **Full CFG construction.** Option C; deferred to Phase 4 if
  needed at all.
- **Loop-carried narrowing.** Guards inside `for`/`while` bodies
  apply on each iteration but don't compose across iterations
  without a CFG with widening. Out of scope; loop bodies get the
  same branch-scoped treatment as plain if-bodies, with no special
  loop semantics.
- **`switch` guards.** Each case-body gets its scope, but no
  fall-through analysis (a case without `break` is the same as
  a sequential block today). Acceptable; backend switches
  rarely use fall-through deliberately.
- **Custom validator inference (without LLM).** Recognising that
  `function isValidId(x): x is string { ... }` is a TS user-
  defined type guard would require type-aware analysis. Out of
  scope; user can declare it in `stryx.toml` (deferred to
  [ADR 0010](0010-external-library-summaries.md)).
- **Inter-procedural guard tracking.** A guard inside a helper
  doesn't propagate to the caller through the function summary.
  Per-call inlining of guard effects is exponential; deferred.

## Consequences

### Positive

- **The most common AI-emitted positive-branch sanitisation
  pattern stops firing FPs.** Single biggest precision win
  available without leaving v0.3.x's substrate.
- **The catalogue is shared across rules** via the ADR 0008
  registry. `MembershipGuard` recognised once, consumed by every
  flow rule.
- **Existing early-return narrowing keeps working unchanged.**
  Slice 9.1+ introduces it as a special case of the same
  recogniser; the user-visible behaviour is identical for that
  case until a different shape lands.
- **Layer 3 escalation gets a focused budget.** Slice 9.6 sends
  custom-validator-shaped zones to LLM only; the structural
  patterns are all AST-decidable.

### Negative

- **Behaviour change at slice 9.3.** Findings disappear from the
  positive-narrowing pattern. OSS sample diff is expected and
  documented; needs explicit changelog entry.
- **Branch-scope correctness tests are non-trivial.** Re-taint-
  inside-branch, late-narrowing, nested guards, ternary inside
  if-body — each is a unit test the engine didn't have before.
- **`Cell::clean()` semantics under merge.** ADR 0006 invariant:
  `Clean ⇒ Bot`. Branch-scope overrides write `Cell::clean()` at
  the override layer; if the parent scope holds `Tainted+Obj{...}`,
  a child-scope `Clean+Bot` shadows the parent in lookup but does
  not merge into it. The Semgrep deep-dive flagged Semgrep's
  `Clean ⊔ None` merge as a "THINK" comment; we resolve it
  conservatively (the override hides taint inside the scope, full
  stop). Documenting the resolution here closes the related ADR
  0006 follow-up.

### Neutral

- **Function summary contract unchanged.** Branch-scope overrides
  are visitor-local; they don't enter `ParamFlow` or
  `ExportedFunctionSummary`. Cache key (ADR 0005) unaffected.
- **Convergence model unchanged.** Iteration cap from ADR 0004
  carries over; lattice height stays finite.
- **LLM escalation surface grows by one zone-kind (slice 9.6) but
  is bounded by the recogniser's `None`-fallback discipline.

## Notes

### OSS validation criterion

Slice 9.3 is the first slice with expected finding-level diff.
The pass criterion is: every disappeared finding on the OSS
sample is independently verified — by hand, on the source — to
be a true positive in the *narrowed* sense (the guard does in
fact protect the sink). Any false-narrowing case (guard recognised
but doesn't actually clear the taint) blocks the slice until
fixed.

Slice 9.7 (schema-discriminant) ships only after slice 9.3's
baseline is validated, so the diff at slice 9.7 attributes
cleanly to schema guards.

### Reversibility

Each slice reverts cleanly:

- 9.1 — delete the substrate; no consumer depends on it.
- 9.2 — remove `push_branch_scope`/`pop_branch_scope`; visitor
  reverts to single-scope semantics.
- 9.3 — flip a `cfg(feature = "guard_narrowing")` flag; visitor
  bypasses guard recognition. Old early-return narrowing keeps
  working via the legacy `collect_includes_narrowed` path.
- 9.4 — drop the `ConditionalExpression` consumer; ternaries
  revert to taint-union semantics on both arms.
- 9.5 — drop assert recognition.
- 9.6 — drop the `UncertainZone` emission; LLM escalation
  surface returns to its pre-9.6 size.
- 9.7 — drop `SchemaSuccessGuard`; revert to the imperative
  `.parse()` recogniser only.

### Performance

The per-statement cost is one `recognise_guard` dispatch and (on
match) one scope push/pop. The dispatch is a closed-enum match,
~10 cycles. The scope clone (slice 9.2 TBD: clone vs fresh-push)
is the larger cost; benched against the existing 1ms-per-rule-per-
file budget. If clone-cost dominates, the alternative is a sparse
override map keyed by name, layered atop the parent scope —
deferred until benches show the cost matters.

### Provenance and licensing

The branch-scope-pushdown mechanism is an extension of Stryx's
existing scope stack (introduced in slice 3.5 of ADR 0007). The
guard-recognition catalogue is informed by CodeQL's
`BarrierGuards.qll` (MIT, no code reused) and Semgrep's sanitiser-
node model (LGPL-2.1, no code reused). Algorithmic-design
references only; `THIRD_PARTY_LICENSES.md` requires no entry.

### Relationship to ADR 0008

`GuardKind` is a `StepKind` variant per ADR 0008's substrate. The
guards module lives at
`crates/stryx_rules/src/steps/sanitisers/guards/`, slotted into
the existing `sanitisers/` subdirectory. ADR 0008 must land
through slice 8.3 (sanitiser migration) before ADR 0009's slice
9.1 can land cleanly. If ADR 0008 stalls, ADR 0009's slice 9.1
ships standalone in `crates/stryx_rules/src/flows/guards/` and
gets relocated when ADR 0008 catches up.

## References

- [ADR 0003](0003-cross-file-and-taint-as-core.md) — cross-file
  taint as v0.1 core; the per-function summary contract is
  unchanged by branch-scope overrides.
- [ADR 0004](0004-two-pass-fixpoint-with-iteration-cap.md) —
  driver loop; branch scopes are visitor-local, no convergence
  impact.
- [ADR 0005](0005-taint-aware-cache-keys.md) — cache key contract;
  unaffected.
- [ADR 0006](0006-shape-lattice-taint-summary.md) — shape lattice;
  `Cell::clean()` is the override value. The `Clean ⊔ None`
  resolution noted there is anchored by this ADR.
- [ADR 0007](0007-return-shape-tracking.md) — return-shape
  tracking; slice 9.7 (schema-discriminant) consumes return shapes.
- [ADR 0008](0008-taint-step-trait-substrate.md) — step-trait
  registry; this ADR's `GuardKind` is a step variant.
- [`crates/stryx_rules/src/flows/unvalidated_body_to_db.rs:115`](../../crates/stryx_rules/src/flows/unvalidated_body_to_db.rs)
  — `allow_lists`; the existing collector stays.
- [`crates/stryx_rules/src/flows/unvalidated_body_to_db.rs:1886`](../../crates/stryx_rules/src/flows/unvalidated_body_to_db.rs)
  — `collect_includes_narrowed`; the legacy recogniser becomes a
  `MembershipGuard` special case at slice 9.3.
- CodeQL — `BarrierGuards.qll` (MIT). Polarity-typed guard model
  inspiration.
- Semgrep — sanitiser-node dataflow model (LGPL-2.1). Contrast
  case: their model doesn't handle Problem 1 cleanly either.
