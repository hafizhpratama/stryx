# `stryx_ast`

The normalised AST surface — Stryx's swappable-parser boundary.

## What this crate provides

- Re-exports from `oxc_ast` (the parser-produced AST) and
  `oxc_ast_visit` (the `Visit` walker).
- `to_span` — adapt an `oxc_span::Span` to Stryx's
  [`stryx_core::Span`](../stryx_core).
- The local `Visit` re-export is the visitor trait every rule
  consumes.

## Why this exists

[AGENTS.md](../../AGENTS.md) engineering rule: rules must not import
oxc types directly. All AST surfaces flow through this crate so
the parser is swappable. Test: replacing `oxc_parser` with
another implementation should require zero changes to
`stryx_rules`. Today the re-exports are thin pass-throughs;
future parsers may require adapters.

## Stability

Public surface mirrors oxc's at the granularity rules need.
Major-version oxc bumps may break here; rule code should not.
