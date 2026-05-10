# ADR 0004 — Two-pass extract→run pipeline with bounded fixpoint

- **Date**: 2026-05-10
- **Status**: Accepted (formalises an implicit decision shipped during slice 1/2)
- **Decider**: Hafizh Pratama
- **Supersedes**: none
- **Refines**: [ADR 0003](0003-cross-file-and-taint-as-core.md)

## Context

ADR 0003 committed v0.1 to cross-file taint analysis. It described
the per-function summary model and the source/sink/sanitizer
vocabulary, but did not pin down the *driver loop*: in what order
files are visited, how summaries reach summaries, and what happens
when the call graph is deeper than the loop's bounded depth.

This ADR was originally numbered 0004 and left as a gap during
slice 1/2 work; the current driver shape (in
`crates/stryx_cli/src/lib.rs`) was implemented and shipped without
a written record. This ADR backfills that record after the fact —
it documents the decision that is already in production code, not
a new one. The two follow-on slices that depend on it (slice 2 v3
sanitisers; the convergence signal added during the audit pass)
made the contract load-bearing enough that leaving it implicit
became a liability.

The driver-loop question has three connected parts:

### Question 1: how do summaries reach summaries?

A handler imports a service which imports a repository. To know
whether the repository writes tainted data to the DB, the rule
must analyse the repository *first*, attach a summary, then
analyse the service with the repository's summary visible, then
analyse the handler with the service's summary visible. With
multi-level chains (controller → service → repository) the order
is non-trivial: in the general case there's no topological order
because TypeScript projects routinely have cycles between modules.

### Question 2: when does the analysis stop?

A monotone fixpoint over a finite lattice always terminates, but
"finite" depends on lattice height. The current `ParamFlow` lattice
is one boolean per param per predicate — finite, but only in
principle. We need a concrete loop bound that holds in practice and
fails loudly when it doesn't, so that under-approximation never
becomes a silent correctness bug.

### Question 3: how do we detect convergence?

Comparing two `ProjectIndex` snapshots structurally is too
expensive for a per-round check. We need a *cheap* convergence
signal that is also *complete enough* — a signal that flips when
*any* summary axis changes, not just one.

## Options considered

### Option A — Single pass, no fixpoint

Walk every file once. Rules see only their own file plus
already-extracted summaries from files visited earlier in the
walk.

**Pros:**
- Trivially fast — one parallel pass over files.
- No termination question.

**Cons:**
- Walk order matters: helpers visited *after* their callers see
  empty summaries from those callers, so chains break depending on
  filesystem order.
- Cycles between modules silently under-approximate.
- Catching multi-level call chains (controller → service →
  repository) requires file order matching call depth, which is
  not knowable a priori without a graph.

Rejected — non-deterministic precision is worse than no precision.

### Option B — Topological sort the import graph, then single pass

Build the import graph, condense SCCs, run rules in reverse
topological order so callees are summarised before callers.

**Pros:**
- Each file is visited once after its dependencies.
- Standard compiler-frontend pattern; well-understood.

**Cons:**
- SCC condensation is real engineering. Inside an SCC we still
  need a fixpoint anyway, so this is not a simpler model — it's a
  different driver loop *plus* a fixpoint inside SCCs.
- TypeScript projects have many small cycles in practice
  (re-exports, framework conventions); SCCs are not rare.
- The complexity is wrong-for-now. v0.1 is shipping the *first*
  cross-file flow rules; we don't yet have the data to know
  whether SCC-aware ordering buys real precision over a naive
  fixpoint.

Deferred. Reconsider at v0.3 when the lattice (per ADR 0006)
starts producing summaries large enough that a redundant round
becomes visible in benchmarks.

### Option C (chosen) — Iterative two-pass extract→run with iteration cap

```
Pass 1 (extract, repeat until fixed point or cap):
  for round in 0..MAX_ITER:
    prev_index = current_index
    summaries = par_map(files, |f| extract(f, prev_index))
    next_index = ProjectIndex::from(summaries)
    next_index.set_path_aliases(...)
    next_index.finalize()
    if convergence_signal(next_index) == convergence_signal(prev_index):
      converged = true; break
    current_index = next_index
  if not converged: tracing::warn!(...)

Pass 2 (run, single pass):
  findings = par_flat_map(files, |f| run(f, current_index))
```

**Pros:**
- Each round is fully parallel — files within a round are
  independent because they all read the *previous* round's index,
  not each other's in-flight state. Maps cleanly onto rayon.
- No graph construction; cycles handled implicitly by iteration.
- The lattice is a join-semilattice over booleans (and per ADR 0006
  Phase 1, over offset sets); monotone updates in summary fields
  guarantee progress until a fixed point. Termination is bounded by
  call-graph depth, not by lattice height *per se*.
- The cap is a *safety net*, not the termination argument: if the
  analysis didn't converge in N rounds, soundness is announced as
  uncertain via a tracing warning. A hidden bug is louder than a
  hidden FN.
- Two-phase split keeps run-time concerns (finding emission)
  separate from extract-time concerns (summary computation),
  matching the contract test in `ARCHITECTURE.md`: "no rule writes
  to a finding during extract, no rule writes to a summary during
  run."

**Cons:**
- Re-analyses every file every round. With `MAX_ITER = 10` and
  4-round average convergence on real Next.js apps, that is 4×
  the per-file cost vs Option B. Acceptable at v0.1 scale (per-file
  budget is 10 ms, 10k files in 30s — we are well within budget).
- The iteration cap is a magic number. Set too low, deep call
  chains under-approximate silently (mitigated by the convergence
  warning). Set too high, scan time on pathological codebases
  inflates without precision gain.
- Convergence detection complexity is a tax: ADR 0003 is silent on
  what "converged" means, and a naive snapshot-equality check is
  expensive. We need a cheap signal — see Question 3 below.

### Option D — Worklist-style fixpoint over functions

Maintain a worklist of functions whose summary changed; re-analyse
only the callers of changed functions until the worklist is empty.

**Pros:**
- Optimal work — each function is re-analysed only when one of its
  callees has a new summary.
- Standard dataflow analysis pattern.

**Cons:**
- Requires a reverse call graph (callee → callers) maintained
  incrementally. We don't have that data structure yet, and
  building it is roughly the same cost as Option B's SCC
  condensation.
- Mutates shared state during the round, which forces serialised
  or carefully synchronised access — moves us off rayon's
  par-map model and into a `crossbeam-channel` worklist model,
  which CLAUDE.md explicitly steers against without justification.
- Premature optimisation at v0.1: we don't yet know which axis
  (rounds × files, vs file × rule cost) dominates in practice.

Deferred. Reconsider when benchmarks show the redundant-rounds
overhead exceeding 20% of scan time on the integration suite.

## Decision

**Option C — iterative two-pass extract→run with `MAX_ITER = 10`
and a tuple-shaped convergence signal.**

The driver loop is the one currently in
`crates/stryx_cli/src/lib.rs`:

```rust
const MAX_ITER: usize = 10;
let mut project_index = ProjectIndex::new();
let mut prev_signal: Option<ConvergenceSignal> = None;
let mut converged = false;
let mut last_signal = ConvergenceSignal::default();
for round in 0..MAX_ITER {
    let prev = Arc::new(project_index);
    let summaries: Vec<FileSummary> = files
        .par_iter()
        .flat_map_iter(|f| extract_file(f, &registry, &sources, &prev))
        .collect();
    let mut next = ProjectIndex::new();
    for summary in summaries { next.insert_file(summary); }
    next.set_path_aliases(path_aliases.clone());
    next.finalize();
    let signal = convergence_signal(&next);
    last_signal = signal;
    project_index = next;
    if let Some(prev) = &prev_signal && *prev == signal {
        converged = true; break;
    }
    prev_signal = Some(signal);
}
if !converged {
    tracing::warn!(
        max_iter = MAX_ITER, ?last_signal,
        "extract pass exited via iteration cap without reaching a fixed point — \
         call chains deeper than {MAX_ITER} hops may be under-approximated. \
         Set RUST_LOG=stryx_cli=debug to see per-round signals."
    );
}
```

### Convergence signal contract

The signal is a tuple of independently-counted summary axes:

```rust
pub struct ConvergenceSignal {
    sink_params: usize,             // # of params with reaches_db_sink_unsanitized = true
    propagating_params: usize,      // # of params with propagates_to_return  = true
    body_validated_handlers: usize, // # of validate-wrapped handler exports
}
```

Equality of two consecutive signals declares the round converged.
The original implementation used only `sink_params`; that produced
*premature* convergence when a propagation flag flipped on round
N+1 without changing the sink count. The audit pass added the
remaining axes; **any new summary boolean must extend
`ConvergenceSignal` in lockstep, or the loop will silently
under-detect via that axis again.** This is a contract-test
requirement — a unit test in `stryx_taint` enforces that every
public boolean field on `ParamFlow` and `ExportedFunctionSummary`
is referenced in `convergence_signal()`.

### `MAX_ITER = 10` justification

The cap was chosen empirically:

- Real Next.js apps in the OSS validation suite converge in 2–4
  rounds.
- Synthetic stress fixtures (controller → service → repository →
  helper → util → adapter chains) converge in ≤ 6 rounds.
- 10 leaves headroom for one-or-two additional levels in v0.2
  rules without re-tuning.
- 10 keeps the worst-case scan time inside the 30s/10k-file budget
  from `ARCHITECTURE.md` (per-round cost ≈ 3s on the integration
  suite).

The tracing warning on cap-out is the explicit safety valve. It
fires today on no fixture in the test suite; if it ever fires on a
real codebase, the right response is to investigate the depth
*first*, not bump the cap.

### Soundness statement

The analysis is **bounded-iteration sound**: any finding emitted
during pass 2 corresponds to a summary that was monotonically
derived during pass 1. The soundness gap is one-directional —
flows requiring more than `MAX_ITER` hops may be missed (false
negatives), but false positives are not introduced by the loop
shape. The convergence warning makes the gap observable rather
than silent.

This is weaker than the unconditional soundness a worklist
fixpoint would give. The trade is intentional: deterministic
parallelism + observability + simple termination, in exchange for
a finite-depth cap that is currently far above the depths real TS
projects exhibit.

## Consequences

### Positive

- Fully deterministic per round; no walk-order dependence between
  rules or between files. The same input produces the same
  `ProjectIndex` byte-for-byte across runs (verified in
  `crates/stryx_taint/tests/cache_key.rs` per ADR 0005).
- Clean parallelism story (rayon par-map per round) without
  shared-mutable-state primitives. Aligns with CLAUDE.md hard
  rule #4 ("no `Arc<Mutex<_>>`").
- The two-phase split (extract / run) maps directly to the
  `Source` / `Sink` / `Sanitizer` / `Flow` rule kinds from ADR
  0003: extract is "what does this file *say* about taint";
  run is "what does this file *do* with taint already known."
- Failure mode is loud: the cap-out warning surfaces silent
  under-approximation. No-op in CI today (no fixture trips it),
  but ready to fire if a real codebase needs it.
- Convergence signal is content-addressable; ADR 0005's cache key
  can incorporate it as part of the bail reason if we ever need
  to invalidate cache entries from cap-outs separately from
  converged scans.

### Negative

- **Redundant work per round.** Files are re-analysed even when
  their dependencies haven't changed. Acceptable today; flagged
  for re-evaluation at v0.3 when summaries grow.
- **Cap is a magic number.** `MAX_ITER = 10` is not derived from
  first principles; it's empirically chosen. We accept this and
  surface it via the warning.
- **Convergence signal is a contract.** Adding any new summary
  boolean without extending `ConvergenceSignal` reintroduces the
  silent-under-detection bug the tuple-shape was specifically
  designed to fix. A unit test in `stryx_taint` enforces this; if
  you bypass the test you reintroduce the bug.
- **Soundness is bounded, not unconditional.** Documented above
  and surfaced via tracing. v0.2 should consider emitting an
  `UncertainZone` for cap-outs so Layer 3 LLM escalation can
  patch the gap on demand (per ADR 0002).

### Neutral

- The two-pass split is independent of the lattice shape — ADR
  0006's shape lattice migration changes *what* the summary
  carries, not *how* the loop drives it. Phase 1 and Phase 2 of
  ADR 0006 both compose with Option C unchanged.
- Cache key strategy (ADR 0005) is unaffected; the loop produces
  the same `ProjectIndex` shape on every converged scan.
- Layer 3 LLM escalation (ADR 0002) is unaffected — escalation
  fires per UncertainZone, not per round.

## Notes

### Cap-out as an UncertainZone (v0.2 follow-up)

The current behaviour on cap-out is a tracing warning and silent
under-approximation. A natural v0.2 extension is to emit an
`UncertainZone` covering each function whose summary changed in
the last round before cap-out — Layer 3 can then take a closer
look at exactly the call sites the bounded loop missed.

Out of scope for this ADR; tracking note for the v0.2 plan.

### Worklist as the natural successor

If benchmarks ever show redundant-rounds work dominating scan
time, the next driver shape is Option D (worklist over functions).
The convergence signal already gives us per-round per-axis deltas;
a worklist would consume those deltas directly. The migration is
local to `stryx_cli::scan` and the rule trait API doesn't change.

### `finalize()` is part of the contract

`ProjectIndex::finalize()` resolves re-export chains, applies
path-aliases, and computes derived fields. It must be called *once
per round, after all summaries are inserted, before
`convergence_signal()` is computed*. Calling it earlier produces
incomplete derived state; skipping it produces non-deterministic
flows on barrel-file fixtures. The driver loop above respects
this contract; future drivers must too.

### Reversibility

High. The driver loop is local to `crates/stryx_cli/src/lib.rs`;
swapping it for a worklist or topological driver does not touch
the rule library, the AST, the index, or the cache. Each
alternative is a self-contained PR.

## References

- [ADR 0003](0003-cross-file-and-taint-as-core.md) — cross-file
  taint as v0.1 core; defines the summary contract this driver
  iterates over.
- [ADR 0005](0005-taint-aware-cache-keys.md) — cache keys; this
  driver produces the deterministic `ProjectIndex` snapshots that
  make taint-summary hashing reproducible.
- [ADR 0006](0006-shape-lattice-taint-summary.md) — shape lattice;
  composes with this driver unchanged.
- [`docs/architecture/taint-engine.md`](../architecture/taint-engine.md)
  — engine overview; references the driver loop directly.
- [`crates/stryx_cli/src/lib.rs`](../../crates/stryx_cli/src/lib.rs)
  — implementation of record.
