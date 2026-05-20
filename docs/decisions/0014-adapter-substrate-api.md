# ADR 0014 — Adapter substrate API

- **Date**: 2026-05-20
- **Status**: Proposed
- **Decider**: Hafizh Pratama
- **Refines**: [ADR 0008](0008-taint-step-trait-substrate.md),
  [ADR 0013](0013-stack-aware-project-profiles.md)

## Context

[ADR 0013](0013-stack-aware-project-profiles.md) committed Stryx to a
`ProjectProfile` + `StackAdapter` architecture. v0.3.0 shipped the
profile half — Stryx now detects runtime, framework, data layer,
validator, auth, LLM SDK, and deployment from package metadata.

The profile is currently inert: no rule reads it, no detection logic
branches on it. The 11 existing rules still carry framework knowledge
inline (source recognizers for `req.body`, `c.req.json()`,
`searchParams.X`; sink recognizers for `prisma.*`, `db.insert`,
`sql.raw`; sanitiser recognizers for `zod.parse`, `schema.safeParse`;
auth wrappers; etc.).

That inline approach has hit its scaling limit:

- The v0.3.0 dogfood test on a real NestJS codebase returned zero
  findings because `@Body() dto` is not in any rule's source list.
  Adding it inline would require touching every body-flow rule (7+
  of them).
- Each new framework currently means editing every flow rule's source
  list, every body-source recognizer, every sanitiser shape. The fan-
  out is multiplicative and gets worse as the rule count grows.
- Per-rule edits make it hard to ship "broad adapter pass for all
  P0/P1 stacks" (the v0.4.0 milestone in the revised roadmap) as a
  coherent slice.

The substrate API in this ADR is what makes v0.4.0 implementable.

## Decision

Introduce a `StackAdapter` trait and an `AdapterRegistry`. Each
adapter contributes typed facts (sources, sinks, sanitisers, guards,
propagators) for one stack dimension. Rules consume facts through the
registry, not by hard-coding shapes. The existing `StepKind` substrate
from [ADR 0008](0008-taint-step-trait-substrate.md) stays the
in-engine dispatch enum; adapters supply the pattern data that
`StepKind` variants match against.

### Trait shape

```rust
pub trait StackAdapter: Send + Sync {
    /// Stable namespaced ID — appears in CLI output, JSON, and config.
    fn id(&self) -> AdapterId;

    /// Dimension this adapter contributes to.
    fn kind(&self) -> AdapterKind;

    /// Whether this adapter should be active for the detected project.
    /// Default: true when the corresponding profile hint is present at
    /// confidence >= 0.60. Adapters can override for special cases
    /// (e.g., `runtime/node` is always active because most things
    /// imply Node).
    fn is_enabled(&self, profile: &ProjectProfile) -> bool;

    /// Static pattern lists. `&'static` so registry can keep them
    /// allocation-free and adapters compile down to constant data.
    fn sources(&self) -> &'static [SourcePattern]   { &[] }
    fn sinks(&self) -> &'static [SinkPattern]       { &[] }
    fn sanitisers(&self) -> &'static [SanitiserPattern] { &[] }
    fn guards(&self) -> &'static [GuardPattern]     { &[] }
    fn propagators(&self) -> &'static [PropagatorPattern] { &[] }
}

pub struct AdapterId(&'static str);

pub enum AdapterKind {
    Runtime,
    Framework,
    DataLayer,
    Validator,
    Auth,
    LlmSdk,
    Deployment,
}
```

### Pattern types

Each pattern type carries an ID, the taint role it contributes, and
a list of AST matchers. Matchers are a closed enum (the
`AstMatcher` substrate below) so dispatch is a jump table, not
dynamic dispatch.

```rust
pub struct SourcePattern {
    pub id: &'static str,
    pub label: TaintLabel,
    pub matchers: &'static [AstMatcher],
}

pub struct SinkPattern {
    pub id: &'static str,
    pub sink: SinkKind,
    pub matchers: &'static [AstMatcher],
    pub severity_floor: Severity,
}

pub struct SanitiserPattern {
    pub id: &'static str,
    pub sanitizer: SanitizerKind,
    pub matchers: &'static [AstMatcher],
}

pub struct GuardPattern {
    pub id: &'static str,
    pub guard: GuardKind,
    pub matchers: &'static [AstMatcher],
}

pub struct PropagatorPattern {
    pub id: &'static str,
    pub matchers: &'static [AstMatcher],
}
```

### `AstMatcher` substrate

A closed enum that covers the shapes adapters actually need. Starting
set, derived from existing inline recognizers:

```rust
pub enum AstMatcher {
    /// `req.body`, `req.query`, `searchParams.X` — bare-ident
    /// member access on a known parameter binding.
    MemberOnParam { receiver: &'static str, property: &'static str },

    /// `c.req.json()`, `req.json()` — method call on a known receiver.
    MethodCall { receiver: &'static str, method: &'static str },

    /// `import { X } from "pkg"` then `X(...)` — bare-ident call
    /// whose import target matches.
    ImportedCall { module: &'static str, name: &'static str },

    /// `@Body() dto: Type` — decorated formal parameter.
    DecoratedParam { decorator: &'static str },

    /// `Bun.spawn(...)`, `Deno.serve(...)` — namespace member call.
    NamespaceCall { namespace: &'static str, member: &'static str },

    /// `<schema>.parse(value)`, `<schema>.safeParse(value)` —
    /// any call whose method matches and whose first arg is the
    /// thing being sanitised. Schema identity isn't tracked; the
    /// method name is the signal.
    MethodCallAnyReceiver { method: &'static str },

    /// `class C` decorated with `@Controller(...)` — class-level
    /// shape recognition for framework entry points.
    DecoratedClass { decorator: &'static str },
}
```

Variants are added as adapters need them; each addition is a small
surface change and a parallel registry entry, identical to how
`StepKind` grows per [ADR 0008](0008-taint-step-trait-substrate.md).

### Registry

```rust
pub struct AdapterRegistry {
    adapters: Vec<&'static dyn StackAdapter>,
}

impl AdapterRegistry {
    pub fn builtin() -> Self { ... }

    /// Resolve which adapters apply to this project. Cached per scan.
    pub fn enabled_for(&self, profile: &ProjectProfile)
        -> EnabledAdapters { ... }
}

pub struct EnabledAdapters {
    pub sources: Vec<&'static SourcePattern>,
    pub sinks: Vec<&'static SinkPattern>,
    pub sanitisers: Vec<&'static SanitiserPattern>,
    pub guards: Vec<&'static GuardPattern>,
    pub propagators: Vec<&'static PropagatorPattern>,
}
```

`EnabledAdapters` is the flat, per-scan view rules consult. It's built
once per scan after profile detection and reused by every per-file
visit. The `Vec<&'static SourcePattern>` shape means rules see a
single union list per role; they don't iterate adapters individually.

### Rule integration

`RuleContext` gains adapter access:

```rust
pub struct RuleContext<'a, 'b> {
    pub file: &'a ParsedFile<'b>,
    pub index: Option<&'a ProjectIndex>,
    pub profile: Option<&'a ProjectProfile>,
    pub adapters: Option<&'a EnabledAdapters>,
}
```

Rules query through helper methods on the existing `StepKind`
registry, which now consults `ctx.adapters` for the pattern matches
instead of the previous inline `match`-statements:

```rust
// Before (v0.3.0)
if is_request_body_source(expr) || is_search_params_member(expr) || ... { ... }

// After (v0.4.0)
if ctx.match_source(expr).is_some() { ... }
```

The dispatch returns `Option<&'static SourcePattern>` so rules can
read the pattern's `label` for taint propagation and `id` for
diagnostics.

### Crate location

Adapters live in `stryx_rules` (new module `crates/stryx_rules/src/adapters/`)
alongside the existing rule code. Reasons:

- The trait is consumed by rules; same crate avoids a cross-crate
  dep cycle (`stryx_index` would need to depend on `stryx_rules` for
  type definitions or vice versa).
- The `StepKind` substrate already lives here.
- Existing recognizers being migrated already live here.

Defer extracting `stryx_adapters` as its own crate until either:
- The adapter count or surface justifies the split (~30+ adapters), or
- A third-party adapter ecosystem emerges and needs a stable public
  crate boundary.

## Consequences

### Positive

- **One PR per stack family.** Adding `framework/nestjs` is a single
  file: an adapter struct with pattern lists. No rule edits.
- **Rule code shrinks.** Migrating inline recognizers behind the
  registry removes per-framework branches from each rule file.
- **Adapter coverage is observable.** Reporters can list which
  adapters fired per finding (`source: framework/nestjs`).
- **Config can target adapters directly.** `stryx.toml` can disable
  `framework/express` for a Hono-first project, etc.
- **Profile-driven enablement happens at one point** — `enabled_for`
  — so confidence thresholds and overrides have one decision site.
- **`AstMatcher` is enum-dispatched.** Hot-path cost is identical to
  the current inline `match`-statements.

### Negative

- **Indirection.** Tracing a finding now goes: rule → registry
  lookup → adapter → pattern → matcher. Each layer is small but the
  chain is one hop deeper than inline.
- **Closed-enum maintenance.** `AstMatcher` variants grow as new
  syntactic shapes appear. Each variant is a coordinated change
  (enum, matcher impl, registry consumer). Same pattern as
  `StepKind`; well-understood.
- **Migration risk.** Moving recognizers behind the registry must be
  byte-identical-output. Tests catch this, but the migration PRs
  need careful review.
- **No user-defined adapters yet.** Closed registry; users can't add
  their own without recompiling. Deferred — same trade-off as the
  closed `StepKind` substrate.

## Implementation outline

1. Add the trait definitions and pattern types in
   `crates/stryx_rules/src/adapters/mod.rs`. No behavior yet.
2. Add `AdapterRegistry` with an empty `builtin()`. Compile-clean,
   no rules consume it.
3. Add `EnabledAdapters` and the `enabled_for(profile)` resolution
   logic. Unit-tested against profile fixtures from v0.3.0.
4. Thread `adapters: Option<&'a EnabledAdapters>` through
   `RuleContext`. Default `None`; rules ignore it for one round.
5. Add `ctx.match_source(expr) -> Option<&SourcePattern>` (and peers
   for sinks/sanitisers/guards/propagators). Wired through `StepKind`.
6. Migrate one rule's source recognizer (the flagship,
   `flow/unvalidated-body-to-db`) to use `ctx.match_source` instead
   of inline checks. Output stays byte-identical on every existing
   fixture.
7. Migrate the remaining 10 rules incrementally. One PR per rule,
   each verified against the full fixture suite.
8. Add the first adapter: `framework/nestjs` (the v0.3.0 gap). Make
   the NestJS dogfood project surface real findings.
9. Fan out to the rest of the P0/P1 catalog per the v0.4.0 roadmap.

Steps 1-3 are the substrate slice. 4-6 are the proof-of-concept.
7-9 are the broad pass.

## Open questions

- **Adapter ordering.** When two adapters match the same expression
  (e.g., `framework/express` and `framework/nestjs` both define `req.body`
  shapes), which wins for diagnostics? Probably: union the matches,
  attribute to the highest-confidence enabled adapter. Concrete
  algorithm to be specified in the migration PR.
- **Source-evidence pass.** v0.3.0's profile detector is cheap-pass
  only (package.json + lockfiles). A future ADR will cover source-
  evidence detection during the extract pass. Adapter activation
  rules will need to handle source-evidence-derived hints too.
- **`Severity` floors per adapter.** Some adapters might want to
  raise severity for specific sink + adapter intersections (a
  `Bun.spawn` with body taint is genuinely higher-risk than a generic
  `child_process.exec`). The `severity_floor` field is in the
  pattern shape but the resolution rule isn't specified — defer.
- **Cross-crate boundary.** If `stryx_adapters` ever becomes its own
  crate, the trait and pattern types are the public surface. SemVer
  rules for additive `AstMatcher` variants need to be spelled out
  (additive variants are not breaking for adapter authors; removing
  is).
- **User-defined adapter config.** Allowing users to define inline
  patterns in `stryx.toml` (`[adapter.custom-framework] sources = [...]`)
  is tempting but deferred. The closed-enum approach gets us through
  v0.4.0 and v0.5.0; revisit if a real user need surfaces.

## Non-goals

- Adapter plugin loading (WASM, dlopen, etc.).
- User-defined adapter DSL in config files.
- Per-adapter version pinning.
- Network-fetched adapter packs.
- Auto-installing missing adapters based on profile evidence.
