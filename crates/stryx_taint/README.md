# `stryx_taint`

The inter-procedural taint engine — Stryx's core analysis primitive,
shared with [`stryx_index`](../stryx_index).

## What this crate provides

- **`Xtaint`** — explicit taint status: `None` / `Tainted(Vec<TaintLabel>)`
  / `Clean`. Distinct from "absent."
- **`Shape`** — structural decomposition of a tracked value. Variants:
  `Bot` (bottom — primitive or untracked), `Obj(BTreeMap<Offset, Cell>)`
  (struct/dict with field-sensitive sub-taint), `Arg(ArgId)`
  (polymorphic placeholder — "whatever the caller passed at slot N").
  `Fun(Signature)` is reserved for ADR 0007 slice 3.6 (HOF support).
- **`Cell { xtaint, shape }`** — the Semgrep-derived storage cell.
  Two canonicalize invariants:
  1. `None+Bot` carries no information → dropped.
  2. `Clean` shadows sub-structure → shape must be `Bot`.
- **`Offset`** — `Field(String)` / `Index(usize)` / `Any`. JS/TS
  dot-vs-bracket access (`x.a` and `x["a"]`) collapses to `Field`
  at construction time.
- **`ExportedFunctionSummary`** — per-function summary written by
  the extract pass: `param_shape` (slice 2.5 source of truth),
  `return_shape` (ADR 0007 slice 3.5), `param_flow` (legacy
  derivative).

## Reading order

1. [`docs/architecture/taint-engine.md`](../../docs/architecture/taint-engine.md)
   — engine design overview.
2. [`docs/decisions/0006-shape-lattice-taint-summary.md`](../../docs/decisions/0006-shape-lattice-taint-summary.md)
   — Phase 2 shape lattice design.
3. [`docs/decisions/0007-return-shape-tracking.md`](../../docs/decisions/0007-return-shape-tracking.md)
   — return-shape tracking and the `Fun` placeholder.

## Stability

`Xtaint`, `Shape`, `Cell`, `Offset`, `Signature`, `ArgId`,
`TaintLabel`, `ExportedFunctionSummary`, `ParamFlow` are public.
Wire format (serde) is part of the cache-key contract per
[ADR 0005](../../docs/decisions/0005-taint-aware-cache-keys.md);
incompatible changes bump the workspace major version per SemVer.
