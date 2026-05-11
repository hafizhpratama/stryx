# ADR 0008 — Taint step-trait substrate

- **Date**: 2026-05-10
- **Status**: Proposed
- **Decider**: Hafizh Pratama
- **Supersedes**: none
- **Refines**: [ADR 0003](0003-cross-file-and-taint-as-core.md), [ADR 0006](0006-shape-lattice-taint-summary.md), [ADR 0007](0007-return-shape-tracking.md)

## Context

The taint engine substrate (ADR 0006/0007) is now sound: the
`Cell { Xtaint, Shape }` lattice tracks per-parameter and per-return
shapes, the fix-point driver (ADR 0004) converges deterministically,
and content-keyed summaries (ADR 0005) cache cleanly across runs.

What the engine still lacks is a **shared vocabulary for taint
flow steps** — the predicate-level definitions of "this expression
is a source", "this call is a sink", "this call is a sanitiser",
"this expression propagates taint from one of its sub-expressions
to its result". Today, each flow rule reinvents those predicates
inline in its own visitor.

The damage is visible by counting: `flow/unvalidated-body-to-db`
ships ~2,670 lines, of which roughly 700–800 are private predicate
helpers (`is_request_body_member`, `is_body_source_call`,
`is_sanitizer_call`, `is_db_read_call`, `is_prisma_write_sink`,
`is_drizzle_write_sink`, `is_orm_write_sink`, `is_response_constructor`,
plus the inlined match arms inside `expr_taint`). `flow/secret-to-response`
ships 586 lines with its **own** parallel set:
`is_secret_expr`, `is_secret_env_name`, `matches_credential_pattern`,
`response_sink_label`, `is_response_constructor` (duplicated!),
`is_redactor_call`, `is_boolean_coercion`, `is_json_stringify`.
`flow/auth-bypass-via-wrapper` adds a third set.

Three concrete problems follow from the duplication:

### Problem 1: predicate drift across rules

`is_response_constructor` is defined twice — once in
`unvalidated_body_to_db.rs`, once in `secret_to_response.rs` — with
no compile-time check that they stay in sync. When Next.js 15 added
`Response.json()` as a static factory, only one of the rules picked
it up until the discrepancy was caught manually. The registry would
have made the gap a single-source fix.

### Problem 2: sink/sanitiser combinatorics

When a future rule wants to share a sink with an existing rule
(e.g., `flow/log-injection` reusing `flow/secret-to-response`'s
response sinks plus a new logging sink), it can either copy the
predicate, depend on the other rule's private function (leaky
internals), or extract an ad-hoc helper. None of those compose.
Adding a fourth flow rule today doubles the duplication, not
linearly.

### Problem 3: HOF and external summaries cannot land cleanly

[ADR 0007](0007-return-shape-tracking.md) slice 3.6 introduces
`Shape::Fun(Signature)` for higher-order functions. The consumer
side needs to recognise *callable values flowing as data* — a
predicate that's neither source, sink, nor sanitiser, but a
fourth kind of step. Without a shared substrate for declaring
flow steps, that predicate is forced into yet another inline
match arm in every consuming rule.

External library summaries (the v0.4 candidate from the Semgrep/
CodeQL competitive review) face the same problem from the other
direction: a `stryx.toml`-shipped summary that says "axios.get is
a sink" needs an injection point in the engine. Today there isn't
one — the engine asks rules, not the engine itself, what the sinks
are.

## Architectural question

How do we extract the shared vocabulary without (a) violating
[CLAUDE.md rule #5](../../CLAUDE.md) ("no rule DSL until 30+
rules exist") and (b) regressing the hot-path performance budget
([ARCHITECTURE.md](../../ARCHITECTURE.md): ≤ 1ms per rule per file)?

The two pressures look like they conflict: extraction implies
indirection, indirection threatens enum dispatch (CLAUDE.md hard
rule #3), and a shared schema at the rule-author boundary is
exactly what the "no DSL" rule forbids.

The resolution is to extract **at the engine boundary, in Rust,
with closed-enum dispatch** — not at the rule-author boundary
with a config schema.

## Options considered

### Option A — Step-trait substrate with closed enum dispatch (chosen)

Introduce a new `stryx_taint::steps` module (or a sibling crate
`stryx_steps` if cross-cutting; deferred decision) defining:

```rust
pub trait TaintStep {
    fn as_source(&self, ctx: &StepCtx, expr: &Expression<'_>) -> Option<TaintLabel> {
        None
    }
    fn as_sink(&self, ctx: &StepCtx, call: &CallExpression<'_>) -> Option<SinkSpec> {
        None
    }
    fn as_sanitiser(&self, ctx: &StepCtx, call: &CallExpression<'_>) -> bool {
        false
    }
    fn as_propagator(&self, ctx: &StepCtx, expr: &Expression<'_>) -> Option<PropSpec> {
        None
    }
}

pub enum StepKind {
    BodySource(BodySource),
    EnvSecretSource(EnvSecretSource),
    PrismaWriteSink(PrismaWriteSink),
    DrizzleWriteSink(DrizzleWriteSink),
    ResponseSink(ResponseSink),
    ZodValidatorSanitiser(ZodValidatorSanitiser),
    AuthCheckSanitiser(AuthCheckSanitiser),
    RedactorSanitiser(RedactorSanitiser),
    JsonStringifyPropagator(JsonStringifyPropagator),
    BooleanCoercionPropagator(BooleanCoercionPropagator),
    // ... one variant per shipped predicate
}

impl StepKind {
    pub fn as_source(&self, ctx: &StepCtx, expr: &Expression<'_>) -> Option<TaintLabel> {
        match self {
            StepKind::BodySource(s) => s.as_source(ctx, expr),
            StepKind::EnvSecretSource(s) => s.as_source(ctx, expr),
            _ => None,
        }
    }
    // ... similar dispatch for the other three roles
}
```

Each rule declares its own `&'static [StepKind]` registry as a
top-level constant. Shared steps (e.g. `ResponseSink` used by both
`flow/secret-to-response` and a future `flow/log-injection`) live
in the shared `steps` module and are referenced from each rule's
const array.

`StepCtx` carries the cross-cutting state today wired through
`FlowVisitor` (validation suppression depth, scope stack, project
index handle, file path) — the substrate the predicates need to
make context-sensitive decisions. Today those decisions are made
by passing `&self` to free helper functions that re-pluck what they
need; `StepCtx` makes the dependency explicit.

The flow rule visitor then asks the registry rather than calling
hardcoded predicates:

```rust
// before (today, simplified):
if self.matches_body_call(call) { return true; }

// after:
for step in RULE_STEPS {
    if step.as_source(&ctx, expr).is_some() { return true; }
}
```

**Pros:**

- **No DSL.** Steps are Rust types; the registry is a compile-time
  constant; matching is a closed-enum dispatch. Rule #5 of
  CLAUDE.md is satisfied verbatim — the abstraction is in *engine*
  Rust, not in a *user-facing* schema.
- **Type-safe shared vocabulary.** `ResponseSink` exists exactly
  once. Adding `Response.json()` as a recognised factory is a
  single-source fix.
- **Hot path stays enum-dispatched.** `match self` over a closed
  set of variants compiles to a jump table; no `Box<dyn Trait>`,
  no virtual call. CLAUDE.md hard rule #3 satisfied.
- **Composes with HOF (slice 3.6) and external summaries (v0.4)
  without further surgery.** A new `StepKind::FunPropagation`
  variant slots in alongside the others. An `ExternalSummary`
  variant (v0.4) parses the `stryx.toml` token grammar at startup
  into the same enum.
- **Realigns the workspace layout to CLAUDE.md.** The aspirational
  `crates/stryx_rules/src/{sources,sinks,sanitizers}/` folder
  structure becomes real; today it doesn't exist on disk.
- **Each migration slice is byte-identical.** The new step runs in
  parallel to the old hardcoded predicate; an integration test
  asserts equivalent findings on every fixture; the old predicate
  is deleted only after the new one is dominant.

**Cons:**

- ~2,000 lines of file moves and ~500 lines of new substrate (trait,
  enum, context type, per-rule registry boilerplate). Ship cost is
  real but one-time.
- `StepCtx` adds a layer of indirection between the visitor and
  the predicates. The hot path adds one trait method call per step
  per inspected expression — measurable, but bounded by the closed
  enum size (~10–15 variants in v0.3.x).
- A single match arm for an expression that's both source-detected
  and propagation-detected (e.g., `req.body.token` is a body source
  AND a credential read) becomes two registry passes. This is the
  intended semantic — separating concerns — but adds two `match`
  walks where the inline code today did one.
- Naming. `StepKind` vs `Predicate` vs `TaintRole` — the refactor
  spends some bikeshedding budget on the public-ish surface.
- The current `expr_taint` function, while sprawling, is in one
  file and one match. Splitting it is a real loss of locality
  during reading. Mitigated by the registry being a top-level
  const that lists every applicable step explicitly.

### Option B — Status quo, keep hardcoded predicates per rule

Accept the duplication. New rules copy the helpers they need;
predicate drift is caught (or not) in code review.

**Pros:**

- Zero engine work. The fastest path to v0.3.x feature output.
- The hot path stays exactly as fast as today.
- Code locality wins: every rule is one file you can read top-to-
  bottom without crossing module boundaries.

**Cons:**

- Predicate drift is already happening (Problem 1 above) and will
  worsen with each new rule.
- HOF (slice 3.6) and external summaries (v0.4) have nowhere clean
  to inject. They will either land as more match-arm sprawl in each
  consuming rule, or force the same refactor under deadline pressure
  with consumer code already depending on the shape.
- `flow/secret-to-response` already shows the pattern: 586 lines, ~30%
  of which is duplicated infrastructure. Multiplied across the v0.3
  flow rules listed in CLAUDE.md (`flow/auth-bypass-via-wrapper`,
  `flow/secret-to-response`, planned: `flow/log-injection`,
  `flow/path-traversal`, `flow/ssrf`), the total duplicated surface
  approaches the size of the substrate that would replace it.

Rejected. The duplication cost compounds; the refactor cost is
one-time.

### Option C — Full rule DSL now (YAML or JSON manifests)

Adopt Semgrep's approach directly: define rules in a config schema
(YAML/JSON), parse into in-memory rule objects at startup, dispatch
via a generic interpreter.

**Pros:**

- Maximally declarative.
- Trivially extensible by users without rebuilding the binary.
- Aligns with where the v0.5+ public-rule plugin model is heading
  (per ADR 0003 phase plan).

**Cons:**

- **Directly violates CLAUDE.md hard rule #5** ("No rule DSL until
  30+ rules exist"). v0.3 has three flow rules. The justification
  for a DSL is repetition; we don't have it yet.
- Loses Rust's type safety at the predicate level. A typo in a YAML
  rule manifest is a runtime error, not a compile error.
- Pattern-matching engine is a separate substrate to build,
  document, version, and test. Per the Semgrep deep-dive (May 2026),
  their `Taint_spec_match.ml` is non-trivial and ships years of
  edge-case fixes.
- Performance: every YAML rule load introduces a parse pass and a
  dispatch overhead. The 1ms-per-rule-per-file budget gets harder
  to meet.

Rejected for v0.3. **Reconsider at v0.5+** when the rule count
crosses 30 and the breadth justifies the substrate cost. The
step-trait substrate from this ADR is the natural foundation: a
v0.5 DSL parses YAML rule files into the same `Vec<StepKind>` the
in-Rust rules already produce.

### Option D — Per-rule predicate duplication with shared utility module

Extract only the most obviously-shared predicates (`is_response_
constructor`, `is_prisma_write_sink`) into a `stryx_rules::shared`
module of plain functions. No trait, no enum, no registry — just
shared `pub fn`s.

**Pros:**

- Minimal-disruption fix to Problem 1 (predicate drift). Each
  shared predicate exists once.
- No abstraction overhead. The hot path is identical to today.
- Reversible per-predicate.

**Cons:**

- Solves Problem 1 only; Problems 2 (sink/sanitiser combinatorics)
  and 3 (HOF/external summary injection) remain open.
- Doesn't realign the workspace layout to CLAUDE.md.
- Defers the question, doesn't answer it. When HOF support lands
  in slice 3.6, the inline match arms in each rule's `expr_taint`
  are still the bottleneck — shared predicates don't help there.

Rejected as the *primary* answer; **adopted as a partial-progress
fallback** if the full Option A migration stalls. The shared-utility
module is a structural subset of Option A's `steps/` module — work
done here is not wasted under either path.

## Decision

**Option A — step-trait substrate with closed enum dispatch** is
the v0.3.x refactor target.

The migration follows the same incremental pattern as ADR 0006/0007:
each slice independently shippable, byte-identical-to-prior-output,
and reversible.

### Implementation slices

**Slice 8.1 — substrate module (no consumer):**

- New module path: `crates/stryx_rules/src/steps/` with `mod.rs`,
  empty `sources/`, `sinks/`, `sanitisers/`, `propagators/`
  subdirectories.
- Define `TaintStep` trait with default-no-op methods.
- Define `StepKind` enum with zero variants (initial).
- Define `StepCtx` struct capturing: `&Path` (file), suppression
  depth, `Option<&'idx ProjectIndex>`, scope-stack handle.
- Define `SinkSpec`, `PropSpec` value types (sink severity hints,
  propagation kind tags).
- Module is exported from `stryx_rules` but not yet referenced.
- Slice ships as engine-only; no rule-side change. OSS scan output
  remains byte-identical.

**Slice 8.2 — first source migration (`BodySource`):**

- Move `is_request_body_member` and `is_body_source_call` from
  `unvalidated_body_to_db.rs` into
  `crates/stryx_rules/src/steps/sources/body.rs`.
- Implement `BodySource: TaintStep` with `as_source` returning
  `Some(TaintLabel::UserInput)` for matched expressions/calls.
- Add `BodySource` variant to `StepKind`.
- In `unvalidated_body_to_db.rs`, define a `const RULE_STEPS:
  &[StepKind]` containing `StepKind::BodySource(BodySource)`.
- Add a parallel-call check: the visitor calls *both* the new
  registry path and the old `matches_body_call` path; an `assert!`
  enforces they agree on every expression seen.
- The assertion runs only in `cfg(test)` and `cfg(debug_assertions)`;
  release builds use the new path directly.
- Integration tests confirm byte-identical findings across all
  body-source fixtures.

**Slice 8.3 — sanitiser migration:**

- Move `is_sanitizer_call` (zod/valibot/yup recognisers) into
  `crates/stryx_rules/src/steps/sanitisers/parser.rs` as
  `ParserSanitiser`.
- Move auth-check recognisers from `auth_bypass_via_wrapper.rs` into
  `steps/sanitisers/auth.rs` as `AuthCheckSanitiser`.
- Move redactor recognisers from `secret_to_response.rs` into
  `steps/sanitisers/redactor.rs` as `RedactorSanitiser`.
- Same parallel-assertion pattern as slice 8.2.

**Slice 8.4 — sink migration:**

- Move `is_prisma_write_sink`, `is_drizzle_write_sink`,
  `is_orm_write_sink` into `steps/sinks/db.rs`.
- Move `is_response_constructor` (the duplicated one) into
  `steps/sinks/response.rs`. Both consumer rules now reference the
  single canonical predicate.
- Same parallel-assertion pattern.

**Slice 8.5 — propagation migration:**

- The bulk of `expr_taint` becomes a registry-driven walk. Each
  expression kind that propagates taint (binary `+`, template
  literals, member access, ternary, logical, object/array literals,
  spreads, casts) becomes a `PropagatorStep` variant.
- The match-arm structure stays — propagation is structural — but
  the per-variant decisions are dispatched through the registry.
- The body of `expr_taint` shrinks from ~150 lines to roughly the
  loop and the structural recursion.

**Slice 8.6 — delete the parallel old code:**

- After 8.2–8.5 land and OSS validation passes on the full
  fixture suite plus the OSS sample, delete the legacy `is_*`
  predicates and the parallel-assertion guards.
- Remove `#[allow(dead_code)]` annotations exposed by the deletion.
- Update `flows/mod.rs` and rule docstrings.
- Final commit closes ADR 0008.

**Slice 8.7 — slice 3.6 lands on the registry:**

- HOF support (ADR 0007 slice 3.6) is the first new feature to
  land *after* the registry exists. It adds `StepKind::FunCallable`
  and `StepKind::FunPropagation` variants without modifying any
  existing rule's match arms.
- This is the validation that the substrate composes correctly.
- Tracked in ADR 0007 with a back-reference to ADR 0008.

### Out of scope

- **External summary token grammar (v0.4 candidate).** Separate
  ADR; the substrate from this ADR is a prerequisite, not a
  deliverable.
- **`stryx_steps` standalone crate.** The new module lives inside
  `stryx_rules` for now. If sink/source predicates start to be
  consumed by `stryx_taint` directly (e.g., for cross-rule taint
  composition in the engine itself), promotion to a sibling crate
  becomes worthwhile. Premature today.
- **YAML/JSON DSL.** Per Option C; deferred to v0.5+.
- **Removing the per-rule visitor structure.** Rules still own
  their visitors (the per-rule semantics live there). The registry
  shares vocabulary, not control flow.
- **Procedural-macro registration.** A `#[stryx_step]` attribute
  macro to declare steps would reduce boilerplate but is an opt-in
  improvement, not a substrate requirement. Reconsider when the
  enum has 20+ variants.

## Consequences

### Positive

- **Single source of truth for shared predicates.** `ResponseSink`,
  `ParserSanitiser`, `PrismaWriteSink` exist exactly once. Predicate
  drift becomes a compile-error class, not a behaviour-drift class.
- **Workspace layout matches CLAUDE.md.** The
  `crates/stryx_rules/src/{sources,sinks,sanitizers}/` paths are
  real after slice 8.4.
- **HOF (slice 3.6) and external summaries (v0.4) compose
  cleanly.** Both add `StepKind` variants, neither touches existing
  rules.
- **`flow/log-injection`, `flow/path-traversal`, `flow/ssrf` (v0.3
  rule-library expansion) reuse `BodySource`, `EnvSecretSource`,
  `ResponseSink` directly.** Each new rule starts at hundreds of
  lines, not thousands.
- **The engine becomes more testable.** Each step has a focused
  unit-test surface (matches/doesn't-match for a focused expression
  kind), independent of the visitor's control-flow tests.
- **Rust enum dispatch preserved.** Hot path performance budget
  unchanged in p99 measurements; verified by the existing criterion
  benches before and after each slice.

### Negative

- **One-time refactor cost ~2,000 LOC moved + ~500 LOC new.** Real
  ship cost. Mitigated by the slice-by-slice byte-identical
  migration — never a flag-day.
- **Code locality decreases.** Reading
  `unvalidated_body_to_db.rs` no longer shows the predicate
  definitions inline. The `RULE_STEPS` const lists every applicable
  step explicitly, which preserves *what* gets matched but not
  *how*. New contributors need to follow one extra hop into
  `steps/`.
- **Trait dispatch overhead.** One method call per step per
  inspected expression. Closed-enum match should compile to a
  jump table; we measure with the existing benches before declaring
  the cost negligible.
- **More files in `crates/stryx_rules/`.** ~10–15 new step files
  by the end of slice 8.5. Module discoverability is the trade for
  module focus.
- **`StepCtx` is a non-trivial type to design correctly first
  time.** Underspecified context produces step types that re-pluck
  state ad-hoc; overspecified context becomes a god-struct. The
  v0.2.x visitor's `&self`-borrow pattern is the design baseline.

### Neutral

- **Public-rule API unchanged.** The `Rule` trait at the
  `stryx_rules::Rule` boundary is not the surface this ADR
  modifies. External consumers see no change.
- **Cache key contract (ADR 0005) unaffected.** Step migration
  changes how predicates are *evaluated*, not what gets *recorded*
  in summaries.
- **Layer 3 LLM escalation (ADR 0002) unaffected.** Steps drive
  Layer 2; Layer 3 escalation operates on the resulting
  `UncertainZone`s, which are summary-level constructs.
- **Two-pass extract→run pipeline (ADR 0004) unchanged.**

## Notes

### Performance verification

Before slice 8.5 lands, the existing criterion benches at
`benches/rules.rs` are re-run for both flow rules. The pass-criterion
is **no p99 regression beyond 5%** on any single benchmark. If the
overhead exceeds 5%, the slice blocks until the cause is found and
fixed (most likely culprits: virtual call elision failure, missed
inline, or oversized `StepKind` variant alignment).

### OSS validation criterion

Each slice ships with a "byte-identical findings on the OSS sample
(50+ Next.js repos)" pass-criterion, mirroring the ADR 0006/0007
discipline. Slice 8.5 is the largest behavioural-equivalence test;
slice 8.6 (deletion of parallel old code) is gated on it.

### Reversibility

Each slice is reversible:

- 8.1 — delete the empty substrate module; no consumer depended
  on it.
- 8.2–8.5 — flip the `cfg(debug_assertions)` parallel assertion to
  prefer the old predicate path; the new path becomes dead code,
  removable.
- 8.6 — restore the deleted predicates from git history. The
  one-commit-per-rule discipline keeps this clean.
- 8.7 — drop the new `Fun*` variants; HOF support reverts to the
  pre-3.6 state. Independent of the 8.x rollback.

### Provenance and licensing

The trait-and-registry shape borrows the *interface idea* from
CodeQL's `isAdditionalTaintStep` predicate model (`Configuration.qll`,
MIT) and Semgrep's `taint_inst.preds.is_source/is_sink` dispatch
(`OSS_dataflow_tainting.ml`, LGPL-2.1). No code is reused from
either project. As with ADR 0006/0007, this is an algorithmic-design
reference; `THIRD_PARTY_LICENSES.md` does not need an entry.

### Why not a procedural macro

A `#[derive(TaintStep)]` macro could reduce per-step boilerplate
(default-no-op methods, enum-variant glue). It's deferred because:

1. The current boilerplate is small (5–10 lines per step).
2. Proc-macro debugging cost outweighs LOC savings until the enum
   has ~20+ variants.
3. The macro can be added later without affecting consumers — it's
   a syntactic sugar layer over the same trait.

Reconsider after slice 8.5 lands and the variant count is known.

### The "no DSL" rule, in detail

CLAUDE.md hard rule #5 is "No rule DSL until 30+ rules exist." The
step-trait substrate is **not** a DSL. Specifically:

- It's Rust types, compiled, type-checked, optimised.
- Rule authors write `&'static [StepKind]` arrays in Rust source
  files, not config manifests.
- There is no parser, no schema, no runtime rule loading.
- The "schema" is the `StepKind` enum — closed, owned by the
  engine, evolving with the engine's release cadence.

A YAML/JSON DSL is the *next* layer up, where the same `StepKind`
variants are constructed by parsing user-supplied configuration
at startup. That layer is deferred to v0.5+. This ADR is the
substrate it would build on, not the substrate itself.

## References

- [ADR 0003](0003-cross-file-and-taint-as-core.md) — cross-file
  taint as v0.1 core; per-function summary contract this ADR
  preserves.
- [ADR 0004](0004-two-pass-fixpoint-with-iteration-cap.md) — driver
  loop; step migration touches predicates, not the loop.
- [ADR 0005](0005-taint-aware-cache-keys.md) — cache key contract;
  unaffected by predicate refactor.
- [ADR 0006](0006-shape-lattice-taint-summary.md) — shape lattice
  substrate; the registry consumes shapes via existing helpers.
- [ADR 0007](0007-return-shape-tracking.md) — return-shape tracking;
  slice 3.6 lands on the registry per this ADR's slice 8.7.
- [`crates/stryx_rules/src/flows/unvalidated_body_to_db.rs`](../../crates/stryx_rules/src/flows/unvalidated_body_to_db.rs)
  — primary refactor target.
- [`crates/stryx_rules/src/flows/secret_to_response.rs`](../../crates/stryx_rules/src/flows/secret_to_response.rs)
  — second refactor target; consumer of the shared
  `ResponseSink` and `RedactorSanitiser`.
- [`crates/stryx_rules/src/flows/auth_bypass_via_wrapper.rs`](../../crates/stryx_rules/src/flows/auth_bypass_via_wrapper.rs)
  — third refactor target; consumer of the shared
  `AuthCheckSanitiser`.
- [`docs/architecture/rule-format.md`](../architecture/rule-format.md)
  — rule structure; needs an addendum at slice 8.6 describing the
  registry-and-visitor split.
- CodeQL — `Configuration.qll`, `TaintTracking.qll` (MIT). Interface
  inspiration for the `isAdditionalTaintStep`-style predicate
  registry.
- Semgrep — `OSS_dataflow_tainting.ml`, `Taint_spec_match.ml`
  (LGPL-2.1). Dispatch-shape inspiration for the
  `taint_inst.preds.is_source/is_sink` pattern.
