# `stryx_index`

The project semantic index — a per-scan map from file path to
function-level metadata that flow rules query to resolve
cross-file calls.

The next architecture slice extends this crate with a project profile:
runtime, framework, data-layer, validation, auth, LLM, and deployment
evidence used to enable stack adapters. See
[`docs/architecture/project-profile.md`](../../docs/architecture/project-profile.md)
and [ADR 0013](../../docs/decisions/0013-stack-aware-project-profiles.md).

## What this crate provides

- **`ProjectIndex`** — the top-level concurrent map (`DashMap`).
  Cheaply cloneable; rayon workers share a single instance.
- **`ProjectProfile`** — planned stack-detection record that will sit
  beside the index and explain which adapters are enabled.
- **`FileSummary`** — per-file extraction output: imports, top-level
  exports, locals, class declarations, function summaries.
- **`ImportRef`** — resolved import (module specifier + symbol +
  optional namespace alias). Bare specifiers from `node_modules`
  resolve to `Some(ImportRef { ... resolved_path: None })` so rules
  see the import statement but know we don't have a summary.
- **`ClassInfo`** — minimal class metadata used by the rule visitors
  (methods, decorators, base classes).
- **`ProjectIndex::resolve_summary(file, name)`** — the canonical
  cross-file lookup: "in `file`, what does `name` resolve to (local
  binding / same-file export / imported export)?"

## Reading order

1. [`docs/architecture/semantic-index.md`](../../docs/architecture/semantic-index.md)
   — index design.
2. [`docs/decisions/0003-cross-file-and-taint-as-core.md`](../../docs/decisions/0003-cross-file-and-taint-as-core.md)
   — why cross-file taint is v0.1 core; the extract→run pipeline.
3. [`docs/decisions/0004-two-pass-fixpoint-with-iteration-cap.md`](../../docs/decisions/0004-two-pass-fixpoint-with-iteration-cap.md)
   — fixpoint loop (`MAX_ITER = 10`) and how the index participates.

## Stability

The public API is `ProjectIndex`, `FileSummary`, `ImportRef`,
`ClassInfo`. Internal storage details (DashMap shape) are
implementation choices and can evolve.
