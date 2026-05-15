# ADR 0012 — Wire the shape lattice into the live visitor

- **Date**: 2026-05-15
- **Status**: Proposed (in-flight implementation lands in v0.2.12)
- **Decider**: Hafizh Pratama
- **Refines**: [ADR 0006](0006-shape-lattice-taint-summary.md),
  [ADR 0008](0008-taint-step-trait-substrate.md)
- **Closes**: audit gap #3 from the 2026-05-15 internal review

## Context

ADR 0006 introduced the `Cell` / `Shape` / `Xtaint` lattice in
`stryx_taint` to track field-level taint. By v0.2.11 the substrate
ships and the summary-export pass populates it (`param_shape`,
`return_shape`, `tainted_offsets`), but the live visitor's
`is_tainted(name)` is still a flat `HashMap<String, Cell>::contains_key`
check — the stored `Cell`'s structure is never consulted at the
sink-check site.

Concretely, in `flow/unvalidated_body_to_db.rs`:

```rust
fn is_tainted(&self, name: &str) -> bool {
    self.scopes
        .iter()
        .rev()
        .any(|scope| scope.contains_key(name))
}
```

That's a "binding is in some scope" check, not a "this access path
on this binding is tainted" check. The result is a path-insensitive
over-approximation: `body.safeField` and `body.unsafeField` both
report tainted, even when `body.safeField` has been sanitised
upstream.

The audit verdict was: *"You're paying for shape tracking and
getting none of the precision."*

## Decision

For v0.2.12, **promote the live taint state to consult the `Cell`
lattice**, with a deliberately narrow first slice:

1. Add `is_tainted_at(name: &str, path: &[Offset]) -> bool` to
   `FlowVisitor`. Looks up the binding's `Cell` and asks the lattice
   whether the access path resolves to a tainted leaf.
2. Update `expr_taint`'s `StaticMemberExpression` arm to compute the
   access path (`body.x.y` → `[Field("x"), Field("y")]`) and call
   `is_tainted_at`.
3. Keep the existing `is_tainted(name)` as the whole-value query
   for the existing call sites that don't have an access path
   (cross-file param flow, sink-arg whole-value checks).
4. **Do not yet propagate per-field sanitisation into the `Cell`.**
   That is the *next* slice — for v0.2.12 the live lookup is the
   only change. The `Cell`s stored in `scopes` continue to be the
   whole-value `Cell::tainted` they are today, so behaviour is
   unchanged for `let x = body; sink(x)` style flows. The
   precision win lands when a future slice (v0.2.13+) starts
   marking individual fields as clean after `parse(body.x)`-style
   sanitisation.

This split keeps v0.2.12 a low-risk infrastructure slice: the API
exists, all call sites compile against it, but the over-
approximate behaviour is preserved. v0.2.13 then writes
sanitisation results into specific `Cell` offsets without further
visitor surgery.

### What v0.2.12 is *not*

- Not a precision improvement in itself. Findings on existing
  fixtures are unchanged (asserted by re-running the integration
  suite). v0.2.12's user-visible change is "shape lattice is now
  *load-bearing* — future precision work attaches here instead of
  to a flat HashMap."
- Not a refactor of the existing `is_tainted(name)` call sites.
  Those keep working unchanged.
- Not propagated to non-flagship rules. The flagship is the only
  rule with assignment handling (and therefore the only rule whose
  `Cell`s could carry structured taint usefully). Other rules
  store unit values `()`, not `Cell`s.

## Implementation outline

### Cell-side API additions (`crates/stryx_taint/src/lib.rs`)

```rust
impl Cell {
    /// True iff the access path `path` resolves to a tainted leaf
    /// in this Cell's shape. Empty path = "is the whole value
    /// tainted at the root?". Each Offset narrows the lookup.
    pub fn tainted_at(&self, path: &[Offset]) -> bool { … }
}
```

The implementation walks `path` through `self.shape`, recursing
into `Shape::Obj` / `Shape::Arr` cells, and returns `true` iff
the final cell has `Xtaint::Tainted` or any descendant has a
tainted leaf (we want "is *any* part of this access path
tainted?").

### Visitor-side wiring (`crates/stryx_rules/src/flows/unvalidated_body_to_db.rs`)

```rust
impl FlowVisitor {
    /// Like `is_tainted` but consults the field-level lattice.
    /// Empty path is equivalent to `is_tainted(name)`.
    fn is_tainted_at(&self, name: &str, path: &[Offset]) -> bool {
        for scope in self.scopes.iter().rev() {
            if let Some(cell) = scope.get(name) {
                return cell.tainted_at(path);
            }
        }
        false
    }
}
```

Update the `Expression::StaticMemberExpression` arm of
`expr_taint` to compute the path bottom-up and call
`is_tainted_at`. The path is the chain of `.field` accesses from
the root binding down to the current expression.

### Test plan

- One new integration test that asserts findings on existing
  fixtures are unchanged: `unvalidated_body_to_db_existing_fixtures_unchanged`.
- One new `stryx_taint` unit test: `cell_tainted_at_recurses_obj`.
- The `tainted_offsets` summary-export path is already tested in
  `stryx_taint`'s existing suite — verify those tests still pass.

## Consequences

### Positive

- Closes the audit's #3 gap. Three of four audit recommendations
  shipped after v0.2.12.
- The shape lattice becomes load-bearing rather than observation-
  only — future precision slices (v0.2.13: per-field sanitisation
  write-through; v0.2.14: array-element fan-in/out) can pay off
  immediately instead of going through a substrate-promotion
  step.
- Cheap to revert. The `is_tainted_at` API is additive; the
  existing `is_tainted` keeps working unchanged.

### Negative

- A no-precision-change slice may feel like make-work to a
  reviewer. The CHANGELOG entry must be honest that v0.2.12
  itself doesn't change findings; the value is the unlock for the
  *next* slice.
- One more place where the lattice / visitor boundary needs
  consistent semantics. Future contributors must understand both
  the structural path and the underlying `Cell` shape.

### Neutral

- No public-API breakage. `Finding` / `Span` / `Severity` /
  `Cell` external shape unchanged. `Cell::tainted_at` is additive.
- No CLI/JSON output change.

## Out of scope for v0.2.12

- Writing per-field sanitisation into the `Cell` after `parse(body.x)`
  / `Schema.safeParse(body.x)`. → v0.2.13.
- Propagating field-level taint through `const { a, b } = body`
  destructuring (today this taints `a` and `b` whole-value; with
  field tracking it could taint them at their projected offsets).
  → v0.2.14.
- Wiring the lattice into non-flagship rules. → v0.2.15+.
- `Promise.all([body.x, body.y])` fan-in shape tracking. → v0.3.

## Notes

The audit's specific recommendation was a ~half-day slice. This
ADR splits it into ~2-hour slices so each is a clean
release-able patch with concrete tests. v0.2.12 lands the API
plumbing; v0.2.13 wires the first user-visible behaviour change.
