# Changelog

All notable changes to Stryx are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and Stryx adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Categories

- **Added** — new features
- **Changed** — changes to existing functionality
- **Deprecated** — features still working but being phased out
- **Removed** — features removed in this release
- **Fixed** — bug fixes
- **Security** — vulnerabilities fixed

---

## [Unreleased]

### Added

- `flow/ssrf-via-fetch` slice 2 — cross-file taint detection. The
  extract pass simulates each exported function with one parameter
  pre-tainted and records `ParamFlow::reaches_fetch_sink_unsanitized`
  when the simulation observes a fetch sink. The run pass emits a
  finding at the call site when a tainted argument flows into a
  reach-flagged parameter of a callee resolved via the project
  index. URL allow-list guards inside the callee suppress the
  finding (the simulation walks the same `match_url_allow_list_guard`
  helper as slice 1).
- `ParamFlow::reaches_fetch_sink_unsanitized` (with `#[serde(default)]`
  so pre-slice-2 cache entries deserialize).
- `ExportedFunctionSummary::taints_through_fetch_param(idx)` mirror
  of `taints_through_param`.
- `ExportedFunctionSummary::merge_per_rule_flags` —
  `FileSummary::merge_with` now unions per-rule sink flags on
  export/local collisions so the DB rule and SSRF rule can
  co-extract per-file without dropping each other's reachability
  flags.
- `ConvergenceSignal::fetch_sink_params` per ADR 0004's contract
  (every monotone axis that can change across iterations must be
  in the convergence tuple).

## [0.1.0] — 2026-05-11

First stable release. Closes Phase 1 of [ADR 0003](docs/decisions/0003-cross-file-and-taint-as-core.md)
(cross-file taint as the v0.1 core). The substrate is stable; six
flow rules + one generic rule ship in the registry. ADR 0008
(taint-step trait substrate) closed at slice 8.7; the closed-enum
`StepKind` registry has 14 variants × 6 trait methods = 84 dispatch
sites.

**Real-world validation arc** — eight production-grade Next.js
repos scanned (~28,800 TypeScript files total), zero engine-level
false positives. Zero-finding repos (formbricks, inbox-zero,
typebot, midday, lobe-chat, payload) confirm zod / TRPC / strong
framework validation is recognised correctly. TP-heavy repos
(papermark with 70 findings, dub with 6) catch the TS-cast-on-body
and template-literal-host-injection patterns AI tools produce.

**Performance** — 8,513 TS files scanned in 2.16s on lobe-chat
(~3,900 files/sec), well under the `≤ 30s / 10k files` budget
([ARCHITECTURE.md](ARCHITECTURE.md)).

### Added

- **Rule: `flow/ssrf-via-fetch`** ([docs](docs/rules/flow-ssrf-via-fetch.md))
  — body source → `fetch` / `axios.<method>` / `got` sink. Slice 1
  single-file; slice 2 adds the URL allow-list sanitiser
  (`new URL(x)` + `!ALLOWED.has(parsed.host)` early-return); slice
  3 adds the validator-function form
  (`!isAllowedHost(parsed.host)`). Severity tier split: full-URL
  SSRF emits High; host-pinned template path-injection emits
  Medium.
- **Rule: `flow/redirect-open`** ([docs](docs/rules/flow-redirect-open.md))
  — body source → `NextResponse.redirect` / `redirect` / `res.redirect`
  / `Response.redirect` sink. Slice 1 single-file. Shares the URL
  allow-list sanitiser with `flow/ssrf-via-fetch`.
- **Rule: `flow/path-traversal`** ([docs](docs/rules/flow-path-traversal.md))
  — body source → `fs.<method>` / `fsPromises.<method>` /
  `fs.promises.<method>` sink. Slice 1 single-file.
- **ADR 0008 substrate** (closed) — `TaintStep` trait + closed-enum
  `StepKind` registry with sources, sinks, sanitisers,
  propagators, and HOF substrate. Adding a new rule wires its
  detectors as step variants; visitors consult them via
  `registry_as_*` helpers. Closed-enum dispatch keeps the hot path
  as a jump table per [CLAUDE.md hard rule #3](CLAUDE.md).
- **Step variants shipped at v0.1.0**: `BodySource`,
  `ParserSanitizer`, `AuthCheckSanitizer`, `RedactorSanitizer`,
  `PrismaWriteSink`, `DrizzleWriteSink`, `OrmWriteSink`,
  `ResponseSink`, `FetchSink`, `RedirectSink`, `FsSink`,
  `StructuralPropagator`, `FunCallable` (substrate placeholder),
  `FunPropagation` (substrate placeholder), plus the URL
  allow-list sanitiser helpers shared by SSRF + redirect-open.
- **Kind-specialised source methods** on `TaintStep`:
  `as_call_source(&CallExpression)` and
  `as_member_source(&Expression, &str)` for contexts that don't
  hold a full `&Expression` (chain-element walks, summary
  extraction).
- **Discriminated-union validator pattern recognition** in
  `flow/unvalidated-body-to-db`: `const r = validate(body); if
  (!r.success) return ...` untaints both `body` and `r` past the
  guard. Eliminated 7 false positives observed on trigger.dev's
  `feature-flags.ts` routes.
- **Crate READMEs** for `stryx_taint`, `stryx_index`, `stryx_rules`,
  `stryx_ast`.
- **ADR 0011** — Phase 1 → Phase 2 transition plan with three
  Phase 2 tracks (depth on existing rules, coverage breadth,
  pulling drafted ADRs 0009/0010 into implementation).

### Changed

- **`flow/unvalidated-body-to-db`** routes sanitiser and sink
  checks through the registry instead of calling the underlying
  `is_*` predicates directly (`chain_element_taint`,
  `expr_is_tainted_readonly`, `scan_for_sinks` ChainExpression
  arm). Body-source checks use the new kind-specialised methods.
- **`flow/secret-to-response`** routes redactor checks through
  `RedactorSanitizer` (slice 8.3c) and response-sink detection
  through `ResponseSink` (slice 8.4b).
- **`flow/auth-bypass-via-wrapper`** routes auth-helper recognition
  through `AuthCheckSanitizer` (slice 8.3b).
- **URL allow-list sanitiser helpers** extracted to
  `crate::steps::sanitizers::url_allowlist` and consumed by both
  `flow/ssrf-via-fetch` and `flow/redirect-open` (rule-of-three).
- **Parallel-assert guards deleted** after sufficient OSS validation
  across ADR 0008 slices. The registry is now the single source of
  truth from each rule's visitor.

### Fixed

- **`flow/secret-to-response` false positives** on dub's
  `publicToken` / `embedToken` shapes. `INTENTIONAL_PUBLIC_PREFIXES`
  (`public*`, `embed*`) and `init_looks_like_user_input` helper
  recognise validator-output chains and intentionally-public names.
- **`flow/unvalidated-body-to-db` false positives** on
  trigger.dev's discriminated-union validator pattern
  (`validate(body)` → `{success: true, data} | {success: false,
  error}`).
- **`flow/unvalidated-body-to-db` engine bug** on call-wrapped
  sinks observed on documenso. The conservative fallback now
  records root-level taint when `expr_is_tainted_readonly` returns
  true but no structural shape matches.
- **`flow/unvalidated-body-to-db` recognition** of conform-style
  `parse(formData, { schema })` free-function sanitiser shape
  (trigger.dev FP source).

### Notes

- Public CLI flags, JSON output schema, and rule IDs are now under
  SemVer; backward-incompatible changes require a major bump.
- The three new flow rules (`flow/ssrf-via-fetch`,
  `flow/redirect-open`, `flow/path-traversal`) ship as
  `experimental` status — single-file scope only. Cross-file
  slice-2 extensions are the Track A critical path for v0.2 per
  [ADR 0011](docs/decisions/0011-v01-to-v02-transition.md).

## [0.1.0-alpha.3] — 2026-05-10

Phase 2 substrate of ADR 0006 (field-sensitive shape lattice) is
complete. The full Semgrep-style `Cell { Xtaint, Shape }` lattice
ships with two of three planned variants — `Bot`, `Obj`, `Arg`
(polymorphic placeholder). The HOF `Fun` variant is deferred until
return-shape tracking lands. `param_shape` is now the single source
of truth for taint-flow information; the legacy `tainted_offsets`
and `reaches_db_sink_unsanitized` fields on `ParamFlow` derive from
it via `Cell::has_tainted_leaf` and `Cell::top_tainted_offsets`.

OSS validation against `dub` after the slice-2.5 refactor confirms
byte-identical findings vs the Phase 1 baseline (5 findings,
3 flow/unvalidated-body-to-db + 2 flow/secret-to-response, identical
severity breakdown and message text).

### Added (Phase 2 of ADR 0006)
- `stryx_taint::Shape::{Bot, Obj, Arg}` — the full taint shape
  lattice. `Obj` keys are `Offset`s sorted via the derived `Ord`;
  on the wire, encoded as a sorted sequence of pairs via the
  `offset_map_serde` adapter (JSON requires string keys but `Offset`
  is an enum).
- `stryx_taint::Cell { xtaint, shape }` — Semgrep's `cell = Cell of
  Xtaint.t * shape`. Constructors `Cell::{bot, tainted, clean,
  arg_placeholder}` produce shapes consistent with the two Phase 2
  invariants where possible.
- `stryx_taint::Xtaint::{None, Tainted(Vec<TaintLabel>), Clean}` —
  explicit taint status, distinct from "absent from the parent map."
  Tainted's label list is treated as a set; canonicalize sorts and
  de-duplicates.
- `stryx_taint::ArgId { fn_id, idx }` — content-stable parameter
  identity. Stable across runs so cache keys per ADR 0005 stay valid.
- `Cell::canonicalize` — recursive minimization enforcing both Phase
  2 invariants: `None+Bot ⇒ drop`, `Clean ⇒ Bot`. `None+Arg`
  preserved as the placeholder identity. Idempotent (property test
  `canonicalize_is_idempotent`).
- `Cell::merge_into` — the lattice-join. Xtaint: `Tainted` dominates,
  label sets union with sort+dedupe; `Clean+None` downgrades to
  `None` for conservative correctness. Shape: `Bot` is the identity,
  `Obj` maps union by key with recursive cell-merge; `Arg`
  same-id is idempotent, different-id falls back to `Bot`, concrete
  `Obj` always beats opaque `Arg`.
- `Cell::strip_arg_for(fn_id)` — instantiation primitive that
  replaces matching `Arg` with `Bot`. Substrate for future
  return-shape tracking; not yet wired into the visitor (the
  cross-file site only fires on concrete-shaped callees today).
- `Cell::count_tainted_leaves` — total Tainted leaves reachable
  through this cell. Used by `ConvergenceSignal::tainted_leaf_total`
  to detect shape growth across iterations.
- `Cell::has_tainted_leaf` and `Cell::top_tainted_offsets` —
  derivation methods used by slice 2.5 to compute the legacy
  `reaches_db_sink_unsanitized` boolean and `tainted_offsets` Vec
  from the canonical shape.
- `ParamFlow.param_shape: Option<Cell>` — the new source of truth
  for cross-file taint-flow information. Populated by the visitor
  during summary extraction (slice 2.1c local sinks, slice 2.1d
  cross-file composition). `#[serde(default)]` so pre-Phase-2
  cache entries deserialize as `None`.
- `ConvergenceSignal::tainted_leaf_total` — fifth fix-point axis,
  sum of `param_shape.count_tainted_leaves` across all summarised
  params. Per ADR 0004 contract; finer-grained than
  `tainted_offset_total` because it notices chain-depth growth.
- Per-axis convergence-signal contract test
  `convergence_signal_reflects_param_shape` — guards against
  silent-under-detection regressions.

### Changed (Phase 2 consumer wiring)
- Cross-file finding messages in `flow/unvalidated-body-to-db` now
  list specific callee fields when the helper's shape reveals them.
  `saveProfile(body)` where saveProfile reads `input.{name,email}`
  produces "fields: `email`, `name`" in the message. Whole-value
  pass-through callees (Tainted+Bot shape) emit the same message
  as before — no fields suffix.
- `param_shape` is the single source of truth (slice 2.5). The
  visitor's `top_offsets_seen` parallel state is gone; the legacy
  `tainted_offsets` and `reaches_db_sink_unsanitized` fields are
  computed from the canonicalized shape. A `debug_assert!` in
  `build_summary` cross-checks shape-derived `reaches` against the
  previous `!findings.is_empty()` source — fires if a finding
  emission path is ever added without a matching
  `record_taint_in_arg` call.
- The visitor's per-param simulation in `build_summary` emits
  `Cell::arg_placeholder(arg_id)` for params with no taint
  observations (slice 2.3a), instead of leaving `param_shape` as
  `None`. ArgId is built from the function's name and 0-based
  parameter index. Observation-only at consumers (existing
  consumers handle `Arg` the same way they handled `None`).

## [0.1.0-alpha.2] — 2026-05-10

Phase 1 substrate of ADR 0006 (field-sensitive shape lattice migration)
is complete. All four landed slices are observation-only — no consumer
reads `tainted_offsets` for finding decisions, severity, or
suppression. OSS validation against `dub` and `documenso` confirms
byte-identical findings to the pre-Phase-1 baseline.

### Added (Phase 1 of ADR 0006)
- ADR 0004 (driver loop) — formalises the bounded extract→run fixpoint
  with `MAX_ITER = 10` and tuple-shaped `ConvergenceSignal` already
  shipping in `stryx_cli`. Documents the bounded-iteration soundness
  contract: cap-out produces FNs, never FPs; warning surfaces silent
  under-approximation. Convergence-signal contract enforces per-axis
  test additions for any new summary boolean.
- ADR 0006 (shape lattice migration) — commits to the Semgrep-style
  field-sensitive shape lattice (`Bot | Obj | Arg | Fun`,
  `Cell { xtaint, shape }`) as the v0.3 precision target, with a
  v0.2.x phase landing offset-list `ParamFlow` first. Explicit
  algorithmic-design provenance to Iago Abal's Semgrep work
  (LGPL-2.1, design-only — Stryx reproduces from public comments,
  not code).
- `stryx_taint::Offset` — new public type (`Field(String)`,
  `Index(u32)`, `Any`). JS/TS-aware: `obj.a` and `obj["a"]` unify
  per Semgrep's `Ofld == Ostr` rule.
- `ParamFlow.tainted_offsets: Vec<Offset>` — populated by the per-param
  simulation in `flow/unvalidated-body-to-db`. Records the *outermost*
  field of each tainted member-chain read at a DB sink.
  `body.where.id` records `Field("where")` (closest to base).
  Bare-ident pass-through stays empty (signalled via the existing
  boolean). `#[serde(default)]` keeps pre-Phase-1 cache entries valid
  (deserialise to empty offsets — safe FN-direction default per
  ADR 0005).
- Cross-file site in `flow/unvalidated-body-to-db` records caller-side
  offsets via the same first-field walker, plus absorbs the callee's
  `tainted_offsets` when the caller passes a bare tainted ident.
- `ConvergenceSignal::tainted_offset_total` — fourth axis on the
  fixed-point convergence tuple, tracking total `tainted_offsets`
  length across summaries. Guards against the silent-under-detection
  regression where iteration N+1 resolves a new cross-file callee,
  the offset list grows, but the existing counts don't notice. Three
  per-axis contract tests in `stryx_cli::tests` enforce the ADR 0004
  contract.

### Carried forward from earlier pre-alpha work

The entries below were drafted during pre-alpha development (before
the CHANGELOG started cutting numbered releases). They land
collectively in 0.1.0-alpha.2 because no earlier pre-alpha release
was ever cut.

### Added
- Initial project scaffolding
- Core architecture documentation, including ADRs 0001–0006
- AI agent context files (CLAUDE.md, AGENTS.md, .github/copilot-instructions.md)
- Contributor guidelines
- `flow/unvalidated-body-to-db` now follows class-method calls. Class
  declarations contribute method summaries and field-type maps to the
  project index, and `this.<member>.<method>(arg)` resolves through
  constructor parameter properties (`private readonly userService:
  UsersService`) and class field declarations to the receiving class's
  method summary. NestJS-shaped controllers that delegate to injected
  services are now reachable by cross-file taint.
- `flow/secret-to-response` (slice 1, single-file). Detects
  secret-shaped values flowing into a response-body sink without
  redaction. Sources: `process.env.X` where X matches the secret-name
  regex (`SECRET|KEY|TOKEN|PASSWORD|JWT|PRIVATE|CREDENTIAL|DSN`,
  case-insensitive) and isn't on the public allow-list (`NEXT_PUBLIC_*`,
  `PUBLIC_*`, `NODE_ENV`, etc.); hardcoded credential string literals
  (AWS, Anthropic, Stripe, GitHub, OpenAI shapes); destructured
  identifiers whose key name itself matches the secret regex. Sinks:
  `Response.json`, `NextResponse.json`, `res.json/send/end/write`,
  `c.json/text/html/body` (Hono), `reply.send` (Fastify), and
  `new Response(JSON.stringify(...))`. Sanitisers: `Boolean(secret)`,
  `redact/mask/fingerprint/hash(secret)`. Cross-file flow is deferred
  to slice 2.
- `flow/auth-bypass-via-wrapper`. Catches route handlers wrapped in a
  project-local `withAuth`-shaped function (`withAuth`, `withSession`,
  `requireAuth`, `protected`, etc.) whose definition never calls a
  recognised auth helper (`getServerSession`, `auth`, `getSession`,
  `validateRequest`, `lucia.validateRequest`, `clerk.currentUser`,
  …). Cross-file by design — the wrapper lives in `lib/auth.ts`,
  the handler in `app/api/.../route.ts`. Reuses the project index
  built by `flow/unvalidated-body-to-db`: every function summary
  now carries a `contains_auth_check` flag populated at extract time
  by a shared visitor. Fires only on exports named `GET`/`POST`/etc.
  or `default`, and only when the wrapper resolves to a project-local
  function — `node_modules`-imported wrappers are silently passed
  for v0.0.1 (slice 2 will emit UncertainZones for those).
  This completes the v0.1 flow rule trio (unvalidated-body-to-db,
  secret-to-response, auth-bypass-via-wrapper).
- Library entry point: `stryx_cli::scan(path) -> ScanResult`. Extracts
  the two-pass extract→run pipeline out of `main.rs` so bindings
  (napi-rs and future python/wasm) can call the engine without
  re-implementing the loop. The CLI binary is now a thin clap
  wrapper around the same function.
- `stryx_napi` crate. napi-rs 3 bindings exposing a single `scan(path)`
  function that returns a `ScanReport { findings, total }` to Node.
  `Finding` is flattened to a JS-friendly shape (lowercase severity
  string, file path as string, byte offsets as numbers). The crate
  builds locally with `cd crates/stryx_napi && npm install && npm run
  build`; npm publishing pipeline is intentionally deferred to a
  follow-up commit (CI matrix, code signing, npm credentials).
- `.github/workflows/ci.yml`. Test + clippy + fmt matrix on
  Ubuntu and macOS, gated by `RUSTFLAGS=-D warnings`. Excludes
  `stryx_napi` from the cargo-only lane so the Node toolchain isn't
  required for the basic CI lane.
- `.github/actions/stryx/action.yml`. Composite GitHub Action that
  installs the CLI from source via `cargo install --git` (with cache)
  and runs `stryx scan` on the consumer repo. Inputs: `path`,
  `format`, `fail-on`, `ref`. Suitable for PR gating and pre-deploy
  hooks. Will be swapped to a release-binary download path once
  v0.1.0 ships prebuilt artifacts.

### Changed
- `flow/unvalidated-body-to-db` now downgrades where-only Prisma
  writes from High to Medium. When `req.body` flows ONLY into a
  `prisma.X.update/delete({ where: {...} })` clause (used as a
  primary-key filter, not stored content), the finding fires at
  Medium so a `--fail-on=high` CI gate doesn't break on the
  lower-impact pattern. Drizzle / TypeORM / Mongoose sinks (whole
  arg is content) keep High.
- `flow/unvalidated-body-to-db` now detects validation-wrapper
  patterns at export. When a handler is wrapped at export by a
  function whose body calls `<schema>.parse(req.body)` /
  `safeParse(...)`, the inner handler's `req.body` reads are
  treated as already structurally validated. Inverse of
  `flow/auth-bypass-via-wrapper`: every function summary now
  carries a `validates_request_body` flag populated at extract
  time; FileSummary tracks `body_validated_handlers` for run-pass
  suppression. Recovers the cal.com `vital/save.ts` FP.
- `flow/secret-to-response` no longer taints destructure keys whose
  name is exactly a secret keyword (bare `key`, `token`, `secret`,
  etc.). Compound names (`apiKey`, `accessToken`,
  `STRIPE_SECRET_KEY`) still taint. Recovers the documenso S3
  presigned-URL `key` FP — a name like `key` is overwhelmingly an
  S3 object key, not a credential.

### Coming soon (v0.1, planned)
- Foundational crates `stryx_index` (project semantic index) and
  `stryx_taint` (inter-procedural taint engine), per ADR 0003
- Three v0.1 flow rules: `flow/unvalidated-body-to-db`,
  `flow/auth-bypass-via-wrapper`, `flow/secret-to-response`
- CLI binary distributed via `cargo install` and Homebrew
- GitHub Action for pre-deploy / pre-merge gating

### Coming later (Phase 2+)
- napi-rs npm distribution
- Additional flow rules and single-file table-stakes rules
- Hono and Express framework support via source/sink adapters
- Plugin model for community rules (WASM and/or crate-plugin pattern)
- Type-aware analysis via deeper `oxc_semantic` integration

---

## Release process

When we tag a release:

1. Move all `[Unreleased]` items into a new dated section
2. Tag the commit: `git tag -a v0.1.0 -m "Release 0.1.0"`
3. GitHub Actions builds and publishes to crates.io and npm
4. Release notes are auto-generated from this changelog

## SemVer guarantees

- **MAJOR** version bumps when we change CLI flags, JSON output schema,
  rule IDs, or public Rust APIs
- **MINOR** version bumps when we add rules, add output formats, add
  framework support — backwards-compatible additions only
- **PATCH** version bumps for bug fixes and dependency updates

We try to deprecate features for at least one MINOR cycle before removing
them in a MAJOR release.

## Versioning notes for rules

Rules have their own version implicit in the Stryx version that ships them.
A rule's behavior may improve across versions (catches more correctly,
fewer false positives), but its `rule_id` is stable forever. If we ever
need to change a rule's semantics meaningfully, we'd ship it as a new ID
and deprecate the old one.

[Unreleased]: https://github.com/hafizhpratama/stryx/compare/v0.0.0...HEAD
