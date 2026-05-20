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

## [0.4.0] — 2026-05-20

**Adapter substrate + DX shell.** v0.4.0 closes the loop that v0.3.0
opened: the `ProjectProfile` from v0.3.0 now drives a registered set
of 22 stack adapters (frameworks, runtimes, data layers, validators,
auth, LLM SDKs) that contribute sources, sinks, sanitisers, guards,
and propagator patterns to the generic vulnerability rules. Every
flagship body-source rule (`flow/unvalidated-body-to-db`,
`flow/sql-injection`, `flow/command-injection-via-exec`,
`flow/path-traversal`, `flow/ssrf-via-fetch`, `flow/redirect-open`,
`flow/prompt-injection`, `flow/xss-via-dangerously-set-inner-html`)
plus `auth/bypass-via-wrapper` and `secret/secret-to-response`
consults the active adapter set during taint propagation.

Alongside the substrate, this release ships the DX shell: a default
scan subcommand (`stryx <path>` works without the `scan` keyword),
grouped findings with representative locations, a 0–100 Stryx Score
with severity caps, `--diff <base>` for PR-only CI runs, surface
controls in `stryx.toml`, and a `STRYX_DEBUG_DUMP=1` diagnostic
side-channel.

### Added

- **Adapter substrate** (ADR 0014): `StackAdapter` trait,
  `AdapterRegistry::builtin()`, `EnabledAdapters` flat view,
  closed-enum `AstMatcher` dispatch with seven variants (no
  `Box<dyn>` in hot paths). 22 P0/P1 adapters land in this release —
  runtimes (`node`, `bun`), frameworks (`express`, `fastify`,
  `hono`, `nestjs`, `next`), data layers (`prisma`, `drizzle`,
  `pg`, `mysql2`), validators (`zod`, `valibot`, `joi`, `yup`,
  `ajv`, `class-validator`), auth (`better-auth`, `auth-js`,
  `clerk`), and LLM SDKs (`openai`, `anthropic`).
- `RuleContext.adapters` plus `match_source` / `match_sink` /
  `match_sanitiser` / `match_guard` / `match_propagator` helpers so
  rules consult the active adapter set during visitor traversal.
- Decorator pre-taint substrate —
  `decorated_param_names_for_adapters` walks active
  `AstMatcher::DecoratedParam` patterns, lighting up NestJS-style
  `@Body()` / `@Query()` / `@Param()` flows without rule-side code
  changes.
- **CLI default scan** — `stryx <path>` (no `scan` keyword) runs a
  full scan with current-directory default; the explicit
  `stryx scan` subcommand remains as an alias for scripts.
- **`--verbose`** — restores the per-finding output shape (one
  block per finding) for users piping into grep/regex tools.
  Default output groups findings by `(severity, rule_id)` and
  shows up to three representative locations per group with a
  `+ N more` footer.
- **`--diff <base>`** — scan only files changed vs a git ref. Uses
  `git diff --diff-filter=ACMR <base>...` plus
  `git ls-files --others --exclude-standard` for untracked-not-
  ignored files. Falls back to a full scan when git is unavailable.
- **Stryx Score** — 0–100 health number in the human-mode summary
  line and the JSON `summary.score` field. Severity caps: any
  Critical caps at 49, High at 74, Medium at 89, Low at 99.
- **`stryx.toml [surfaces]`** — per-rule routing to `cli` /
  `prComment` / `score` / `ciFailure`. Default `["cli"]` preserves
  prior behavior. `score` counts toward the score but suppresses
  from CLI output; `ciFailure` forces a non-zero exit independent
  of `--fail-on`. `prComment` is recorded for the v0.6.0 GitHub
  Action PR comment writer.
- **`STRYX_DEBUG_DUMP=1`** — writes a full JSON report to
  `/tmp/stryx-report-<unix-ts>.json` after every scan regardless of
  `--format`, announced via a stderr line. Write failures log at
  `warn` and never fail the scan.
- Reporter footer — `scanned N files in Mms` follows every scan
  output (suppressed only when both counters are zero).

### Changed

- Engine pipeline now constructs `AdapterRegistry::builtin()` and
  resolves `EnabledAdapters` against the detected profile once per
  scan, threading `Some(&EnabledAdapters)` through the extract+run
  passes via `RuleContext.adapters`.
- `ScanResult` gains `file_count: usize` and `elapsed_ms: u128`.
  The former `scan(path)` helper is now a thin wrapper over the new
  `scan_with_options(path, &ScanOptions)` entry point — napi
  binding and integration tests continue to use the helper
  unchanged.
- `write_report` takes a `ReportOptions` struct (verbose flag plus
  scan metadata) instead of ad-hoc trailing args, so future surface
  controls can extend it without churning every caller.

### Documentation

- ADR 0014 (`docs/decisions/0014-adapter-substrate-api.md`) —
  closed-enum `AstMatcher` substrate design.
- `docs/getting-started.md` — documents the `[surfaces]` section
  with a status note covering which sections are wired through
  today.

## [0.3.0] — 2026-05-20

**Stack-aware scanning, Phase 1.** First minor bump of the v0.3.x
cycle ships the `ProjectProfile` skeleton: Stryx now detects the
TypeScript backend stack from `package.json`, lockfiles, and a small
set of config files (`bunfig.toml`, `wrangler.toml`, `vercel.json`,
`tsconfig.json`, etc.) before running rules. Detection is included in
both the human and JSON output. **Zero changes to rule behaviour** —
no existing finding count moves on any current fixture. Adapter
consumption of the profile lands in v0.4.0, vertical-slice
stack-specific recognition in v0.5.0.

### Added

- `stryx_index::profile` module — `ProjectProfile`, `Detected<T>`,
  `Evidence`, `EvidenceKind`, plus hint enums for language, runtime,
  framework, data layer, validator, auth, LLM SDK, and deployment per
  ADR 0013 and `docs/architecture/project-profile.md`.
- `stryx_index::profile::detect(path)` cheap-pass entry point.
  Reads at most ~10 files (package.json, lockfiles, configs); never
  parses source, never makes network calls, never installs anything.
  Errors are logged at `warn` and never propagated — a malformed
  workspace yields an empty profile, not a failed scan.
- Initial detector coverage:
  - `runtime/{node,bun,deno,cloudflare-workers}`
  - `framework/{next-backend,hono,express,fastify,nestjs,elysia,oak}`
  - `data/{prisma,drizzle,kysely,knex,pg,mysql2,mongoose}`
  - `validation/{zod,valibot,yup,joi,ajv,arktype,typebox}`
  - `auth/{better-auth,auth-js,clerk,supabase-auth,lucia}`
  - `llm/{openai,anthropic,vercel-ai-sdk,langchain}`
  - `deploy/{vercel,cloudflare,aws-lambda,netlify,fly-io,docker}`
- `ScanResult.profile: ProjectProfile` field. Additive — existing
  callers of `stryx_cli::scan` keep working.
- `JsonReport.profile: Option<&ProjectProfile>` field with
  `#[serde(skip_serializing_if = "Option::is_none")]`. JSON envelope
  schema string stays `stryx.findings/v1` because the addition is
  byte-identical when no stack evidence is present.
- Compact human profile block at the top of `stryx scan` output, e.g.
  `stack: language: typescript • runtime: bun • framework: hono • ...`.
  Only the top-confidence hint per family is shown; full evidence is
  in JSON.
- `stryx_index::jsonc` — extracted `strip_jsonc` from `stryx_cli` so
  the new profile detector and the existing tsconfig path-alias
  reader share a single JSON-with-comments stripper.
- `tests/fixtures/project-profile/{bun-hono-drizzle-zod,
  next-prisma-zod, express-pg-joi, empty}/` — four synthetic mini
  projects exercising the detector across stacks plus the empty
  workspace baseline.
- `crates/stryx_cli/tests/profile.rs` — integration tests asserting
  the expected hints and confidence floors for each fixture.

### Changed

- `stryx_reporter::write_report` signature gained a
  `profile: Option<&ProjectProfile>` parameter. Internal CLI
  consumers (`cmd_scan`) updated; downstream callers using the
  reporter directly need to pass `None` to opt out.
- `stryx_cli` deletes its local `strip_jsonc` and imports from
  `stryx_index::jsonc::strip_jsonc`. Single source of truth.

### Added (carried forward from pre-0.3.0 Unreleased)

- Documented the stack-aware scanning direction: project profiles,
  stack adapters, stack catalog, target CLI output, and ADR 0013.
- Added `AGENTS.md` as the single source of truth for AI-agent context,
  with `CLAUDE.md` reduced to a compatibility redirect.
- Added a dedicated `generic/hardcoded-secret` rule doc.
- Rule docs now act as fix guides. Every shipped rule documents
  `How to fix` and `What Stryx recognizes` so CLI `Read more` links
  can point to concrete remediation guidance instead of vague best
  practices.
- Contributor, PR, and issue templates updated to require remediation
  guidance for new rules.

### Out of scope for this release (planned for v0.4.0+)

- Source-evidence pass (imports, globals, call expressions).
- `WorkspaceProfile` for monorepos.
- `--profile` flag (print profile + exit).
- `[profile]` section in `stryx.toml` for overrides.
- Adapter consumption of the profile.

## [0.2.15] — 2026-05-15

Patch release. **Assignment handling in non-flagship rules** —
bare reassignments (`q = q + body.id`, `q = body.something`) now
propagate taint in seven rules that previously only watched
variable initialisers. Closes a class of silent false negatives
where the route handler reassigns into a SQL/shell/path string
mid-function.

### Fixed

- `flow/sql-injection`, `flow/path-traversal`,
  `flow/command-injection-via-exec`, `flow/ssrf-via-fetch`,
  `flow/redirect-open`, `flow/prompt-injection`,
  `flow/xss-via-dangerously-set-inner-html`: added
  `visit_assignment_expression` that mirrors the flagship rule's
  behaviour. Tainted RHS taints the LHS binding; clean RHS clears
  prior taint. Only handles bare identifier targets — member /
  pattern targets fall through to the existing walk.
- Same seven rules: `expr_taint` now recognises
  `AssignmentExpression` as evaluating to its RHS. Covers
  assignment-as-expression shapes — `foo(q = body)`,
  `if (q = body) {...}`, `q = (r = body)` — that previously
  returned `false` and missed downstream sinks.

### Added

- `tests/fixtures/flow-sql-injection/assignment-bad.ts` pins two
  reassignment shapes (`let q = "lit"; q = q + body.id; sink(q)`
  and `q = template; let r = q; sink(r)`) that were silent FNs
  before this release.

### Precision example

```ts
// CASE 1 — fires after v0.2.15 (was silent before)
let q = "SELECT * FROM users WHERE id = '";
q = q + body.id; // reassignment now taints q
q = q + "'";
return prisma.$queryRawUnsafe(q); // Critical finding ✓

// CASE 2 — chained reassignment also fires
let q;
q = `SELECT * FROM users WHERE name = '${body.name}'`;
let r = q; // r inherits q's taint
return prisma.$queryRawUnsafe(r); // Critical finding ✓
```

## [0.2.14] — 2026-05-15

Patch release. **Destructuring projection** — `const { a, b } =
body` now binds `a` and `b` at body's actual sub-Cells instead of
whole-value tainting them. Compounds with v0.2.13's per-field
sanitisation: validated fields stay clean through destructuring.

### Added

- `Cell::project_at(offset)` — project a Cell at a single offset.
  Returns the explicit shape entry when present; otherwise
  synthesises a Cell that inherits the root xtaint.
- `Cell::project_path(path)` — project along a multi-segment
  path, walking `project_at` one offset at a time.
- `FlowVisitor::lookup_projected(name, path)` — look up the named
  binding's Cell, projected at `path`. Used by destructuring.
- `FlowVisitor::try_apply_destructuring_projection(pat, init)` —
  when the init is an Identifier-rooted access chain and the
  pattern is an `ObjectPattern`, bind each destructured field to
  the source Cell projected at its offset.

### Changed

- `handle_var_decl` calls `try_apply_destructuring_projection`
  before falling back to the existing whole-value taint loop.
  When projection applies, each binding gets its precise
  sub-Cell; clean fields stay clean, tainted fields stay
  tainted. Skips nested destructuring (`{ user: { id } } = body`)
  and rest patterns — those fall through to the existing
  whole-value path.

### Precision example

```ts
const body = await req.json();
IdSchema.parse(body.id); // body.id Clean
const { id } = body; // id binds Clean (was: tainted before v0.2.14)
prisma.user.findFirst({ where: { id } }); // no fire ✓

const { id: vId, name } = body;
prisma.user.create({
  data: { id: vId, name }, // body.name still tainted → fires
});
```

### Audit gaps remaining

- **Assignment handling in non-flagship rules**: only
  `flow/unvalidated-body-to-db` propagates taint through bare
  reassignments / per-field state. The other 10 rules don't
  track reassignment at all. Targeted for v0.2.15.

## [0.2.13] — 2026-05-15

Patch release. **First user-visible precision win from the shape
lattice work** — per-field sanitisation write-through. When
`Schema.parse(body.x)` runs, `body.x` is now treated as clean for
the rest of the scope, while `body.y` (and every unobserved field)
stays tainted. Closes a class of false positives where the user
validated one field of the body but the visitor still flagged it.

### Added

- `Cell::mark_clean_at(path)` in `stryx_taint` — write-side
  counterpart to `tainted_at`. Materialises `Obj` shape as needed;
  intermediate cells inherit the ancestor xtaint so sibling fields
  at every level continue to reflect whole-value taint.
- `FlowVisitor::mark_clean_at(name, path)` in
  `flow/unvalidated-body-to-db` — looks up the named binding's
  `Cell` and calls `Cell::mark_clean_at`. Invoked from the
  sanitiser-detection path of `expr_taint`.

### Changed

- `Cell::tainted_at` semantics: shape entries now **override** the
  ancestor `Tainted` xtaint (previously, `Tainted` short-circuited
  before consulting the shape). Cells with `Tainted` root + `Obj`
  shape that carves a Clean sub-cell now correctly report clean
  on the carved path while still reporting tainted on unobserved
  fields. Existing fixtures byte-identical because pre-v0.2.13
  Cells were `Tainted+Bot` (no shape entries).
- `flow/unvalidated-body-to-db`'s `expr_is_tainted_readonly`
  member-expression arm now consults `is_tainted_at` when the
  access chain reduces to an Identifier root. Without this, the
  sink-check path would still report `body.x` tainted after a
  successful `parse(body.x)`. Symmetric to the `expr_taint` change
  in v0.2.12.

### Precision example

```ts
const body = await req.json();
IdSchema.parse(body.id);             // body.id now Clean
// CASE A — only the validated field is used:
prisma.user.findFirst({ where: { id: body.id } });  // no fire ✓
// CASE B — the validated field plus an unvalidated one:
prisma.user.create({
  data: { id: body.id, name: body.name },  // fires on body.name ✓
});
// CASE C — deep-path sanitisation:
z.string().email().parse(body.user.email);
prisma.user.create({ data: { email: body.user.email } });  // no fire ✓
```

Pre-v0.2.13: all three would fire on `body.x` taint. After:
only CASE B's `body.name` fires.

### Audit gaps remaining

- **Destructuring field projection**: `const { a, b } = body`
  currently taints `a` and `b` whole-value; should project at
  `body`'s offsets. Targeted for v0.2.14.
- **Assignment handling in non-flagship rules**. The 10
  non-flagship rules don't track reassignment. Targeted for
  v0.2.15.

## [0.2.12] — 2026-05-15

Patch release. **Infrastructure slice — closes the audit's #3
gap.** The shape lattice (`Cell` / `Shape` / `Xtaint`) is now
load-bearing in the live visitor.

This is deliberately a behaviour-unchanged slice: findings on every
existing fixture are byte-identical to v0.2.11. The user-visible
win lands in v0.2.13, when per-field sanitisation starts writing
`Clean` cells into specific offsets — at that point the precision
improvements compound on the foundation laid here.

See [ADR 0012](docs/decisions/0012-live-shape-lattice.md) for the
full design rationale + slicing plan.

### Added

- `Cell::tainted_at(path: &[Offset]) -> bool` in `stryx_taint`:
  walk a `Cell`'s shape along a field-access path and return
  whether the resolved leaf (or any descendant) is tainted.
  Whole-value `Tainted` short-circuits to `true`; whole-value
  `Clean` short-circuits to `false`; `None+Bot` per-path is
  conservatively `false`.
- `FlowVisitor::is_tainted_at(name, path)` in
  `flow/unvalidated-body-to-db`: consult the per-binding `Cell`
  via `Cell::tainted_at`. The existing `is_tainted(name)` remains
  as the whole-value entry point for sites without an access
  path (cross-file param flow, sink-arg whole-value checks).
- `static_member_root_and_path` free helper: decompose
  `body.x.y` into `("body", [Field("x"), Field("y")])`. Returns
  `None` for non-pure chains (e.g. `(x = body).y`) so the
  existing recursive `expr_taint` path observes any side
  effects.

### Changed

- `expr_taint`'s `StaticMemberExpression` arm now uses
  `is_tainted_at` when the access chain reduces to an identifier
  root. Behaviour-equivalent in v0.2.12 (every stored `Cell` is
  still `Cell::tainted` whole-value), but the API is now wired
  for v0.2.13's per-field sanitisation.

### Known gaps (still planned for v0.2.13+)

- **Per-field sanitisation write-through.** When `parse(body.x)`
  sanitises just one field, the visitor should mark
  `body`'s `Cell` Clean at `Offset::Field("x")` instead of
  leaving the whole binding tainted. Targeted for v0.2.13.
- **Destructuring field projection.** `const { a, b } = body`
  currently taints `a` and `b` whole-value; should project at
  `body`'s offsets. Targeted for v0.2.14.
- **Assignment handling in non-flagship rules**. The 10
  non-flagship rules don't track reassignment. Targeted for
  v0.2.15.

## [0.2.11] — 2026-05-15

Patch release. **Real soundness fix — closes the audit's #2 gap.**
Higher-order callback patterns (`.then`, `.map`, `.forEach`,
`.filter` and friends) now propagate taint into the callback's
first parameter, so the body of the callback can see body-tainted
flows that the previous visitor missed entirely.

### Fixed

- **`flow/unvalidated-body-to-db`: higher-order callback
  pre-tainting.** Before v0.2.11, the flagship's custom statement
  walk never recursed into callback bodies and the callback's
  first parameter was a clean binding, so all of these silently
  passed:

  ```ts
  req.json().then((body) => prisma.user.create({ data: body }));
  (await req.json()).map((item) => prisma.user.create({ data: item }));
  (await req.json()).forEach((item) => { prisma.user.create({ data: item }); });
  (await req.json()).filter((r) => r.active).forEach((r) => prisma.user.create({ data: r }));
  ```

  New helpers on the `FlowVisitor`:
  - `walk_higher_order_callback` — enters a callback's scope,
    pre-taints its first parameter from the receiver's taint, then
    walks the body via `handle_function_body`.
  - `receiver_taint_through_chain` — recognises that
    `<tainted>.filter(p)`, `.map(f)`, `.slice(...)`, etc. produce
    a tainted result, so chained patterns
    (`filter(...).forEach(...)`) work end-to-end.
  - `is_higher_order_method` table covering `then` / `catch` /
    `finally` for Promises and `map` / `forEach` / `filter` /
    `flatMap` / `find` / `findIndex` / `findLast` / `findLastIndex` /
    `some` / `every` for iterators.
  - `is_taint_preserving_array_method` table covering
    non-mutating / shape-preserving Array methods.

  `reduce` and `reduceRight` are intentionally excluded — their
  first parameter is the accumulator, not the element; naive
  pre-tainting would over-approximate. Targeted as a future
  precision slice.

### Known gaps (still planned for v0.2.12+)

- **Shape lattice not load-bearing in the live visitor.** Field-
  level precision (`body.safeField` vs `body.unsafeField`) is
  still flat. Targeted for v0.2.12.
- **Assignment handling in non-flagship rules.** Only
  `flow/unvalidated-body-to-db` propagates taint through bare
  reassignments. The other 10 rules don't track reassignment
  at all. Targeted for v0.2.13.

## [0.2.10] — 2026-05-15

Patch release. **Real soundness fix — closes the audit's #1 gap.**
The single most common false-negative pattern in backend handler code
now fires correctly.

### Fixed

- **`flow/unvalidated-body-to-db`: branch-merge soundness.** The
  visitor walked `if`/`else` sequentially with no scope save+union
  at the join point, so this pattern (and the symmetric inverse)
  silently passed:

  ```ts
  let payload = body;             // payload tainted
  if (cond) { payload = clean; }  // consequent untaints
  prisma.user.create({ data: payload });  // missed!
  ```

  Three flavours of the bug are exercised by the new
  `tests/fixtures/flow-unvalidated-body-to-db/branch-merge-bad.ts`
  fixture (CASE 1: consequent untaints, no else; CASE 2: alternate
  taints; CASE 3: consequent taints, alternate untaints). All three
  now fire — previously only CASE 2 fired through last-branch-wins
  luck. New `snapshot_top_scope` / `restore_top_scope` /
  `merge_branch_snapshots` helpers on the FlowVisitor save the
  pre-branch state, walk each branch from the entry baseline, and
  union the post-branch states at the join. Branches that
  unconditionally return/throw are excluded from the join state
  (their post-state is unreachable).

### Known gaps (still planned for v0.2.11+)

- **Higher-order callbacks** (`.then(fn)` / `.map(fn)` /
  `Promise.all([<tainted>...])`): the callback's parameter is not
  pre-tainted from the caller's tainted value. Targeted for
  v0.2.11.
- **Shape lattice not load-bearing in the live visitor**: field-
  level precision (`body.safeField` vs `body.unsafeField`) is
  still flat. Targeted for v0.2.12.
- **Assignment handling in non-flagship rules**: only
  `flow/unvalidated-body-to-db` propagates taint through bare
  reassignments (`x = body.y`); the other 10 rules don't track
  reassignment at all. This is a separate (pre-existing) gap
  uncovered while building the v0.2.10 fixture. Targeted for
  v0.2.13.

## [0.2.9] — 2026-05-15

Patch release. **First real user-facing feature improvement of the
v0.2.x cycle** — suppression comments now actually work. Plus a CI
correctness fix that landed earlier.

A post-publish technical audit confirmed the substrate is sound but
identified three larger soundness gaps (branch-merge,
higher-order callbacks, shape-lattice wiring into the live visitor)
that will be tackled in subsequent v0.2.x patches.

### Added

- **Suppression comments now work.** `// stryx-disable-next-line
  <rule-id>` and `// stryx-disable <rule-id>` were documented in
  four places (rule docs, FAQ, getting-started, npm README) but
  unimplemented in any source file — a docs-vs-code lying gap. New
  centralised post-rule filter (`crates/stryx_cli/src/suppress.rs`)
  recognises `//`, `/* … */`, and JSX `{/* … */}` comment shapes;
  supports line-level and file-level suppression; accepts multiple
  rule IDs per marker; ignores trailing `-- <reason>` prose. Only
  fully-qualified IDs (`flow/sql-injection`) are accepted — short
  names like `sql-injection` are rejected so the common typo
  doesn't silently fail to suppress.

### Fixed

- `ci.yml`: swap `dtolnay/rust-toolchain@master` →
  `actions-rust-lang/setup-rust-toolchain@v1` to fix the
  `cargo test` → `rustup-init` PATH bug on macos-15 runners
  (same fix release.yml got earlier in the v0.2.x cycle). CI
  badge on the npm package page now shows green on every push.

### Known gaps (from the audit, planned for v0.2.10+)

- **Branch-merge unsoundness**: `let x = body; if (cond) { x =
  "safe"; }; db.create({ data: x });` produces a false negative
  because the visitor walks `if`/`else` sequentially with no
  scope save+union at the join point. Single highest-leverage
  soundness fix; targeted for v0.2.10.
- **Higher-order callbacks**: `<tainted>.then(fn)`,
  `<tainted>.map(fn)`, `Promise.all([<tainted>...])` don't pre-taint
  the callback's parameter. Targeted for v0.2.11.
- **Shape lattice not load-bearing**: `Cell`/`Shape` substrate is
  in `stryx_taint` and used for summary export, but the visitor's
  live `is_tainted()` is still flat `HashMap::contains_key` — no
  per-field offset consultation. Field-level precision lands in
  v0.2.12.

## [0.2.8] — 2026-05-15

Patch release. The v0.2.7 main npm package shipped without a
README, so the npm page complained "This package does not have a
README." Adds an npm-audience README (`crates/stryx_napi/README.md`)
and includes it in the published `files` array.

### Added

- `crates/stryx_napi/README.md` — npm-audience README covering
  install, quick start, flags, rule highlights, suppression
  syntax. Listed in `package.json` `files`. Becomes visible on
  npmjs.com/@hafizhpratama/stryx and in `npm view`.

## [0.2.7] — 2026-05-15

Patch release. **The v0.2.6 main npm package shipped broken
(missing `index.js`/`index.d.ts` in the tarball, so
`npx @hafizhpratama/stryx` crashed with `Cannot find module
'../index.js'`).** Subpackages were fine. This release fixes the
publish workflow and republishes a working main package. Use
`@hafizhpratama/stryx@0.2.7` or later.

### Fixed

- `npm-publish.yml`: now downloads `index.js` and `index.d.ts`
  from the GitHub Release in addition to the `.node` binaries.
  Earlier the `gh release download --pattern 'stryx.*.node'` glob
  missed the JS loader + TS declarations even though release.yml
  uploaded them.

## [0.2.6] — 2026-05-15

Patch release. **Distribution change: npm package moves to scoped
namespace `@hafizhpratama/stryx`.** No engine, rule, or public-API
changes.

### Changed

- npm package name `stryx` → `@hafizhpratama/stryx`. New install:
  `npm install @hafizhpratama/stryx` and `npx @hafizhpratama/stryx
  scan`. Platform subpackages also become scoped
  (`@hafizhpratama/stryx-darwin-arm64`, etc.).
- The unscoped subpackages from the partial v0.2.5 publish
  (`stryx-darwin-arm64@0.2.5`, `stryx-darwin-x64@0.2.5`,
  `stryx-linux-arm64-gnu@0.2.5`, `stryx-linux-x64-gnu@0.2.5`)
  remain on npm as orphans and should not be used. They predated
  the namespace switch.

### Why scoped

The unscoped path hit two of npm's automated gates that we
couldn't bypass without contacting npm support:
- `stryx-win32-x64-msvc` was blocked with "Package name triggered
  spam detection" (the `*-win32-*` suffix pattern is on npm's
  spam-block list).
- `stryx` itself was rejected as "too similar to existing package
  `stres`" by npm's name-collision heuristic.
Scoped packages bypass both checks because the scope is uniquely
owned. Examples: `@anthropic-ai/sdk`, `@vercel/*`, `@napi-rs/*`.

## [0.2.5] — 2026-05-15

Patch release. **CI fix only — no engine, rule, or public-API
changes.** Same shape as v0.2.4 but applied to the napi build
matrix entry too: v0.2.4 fixed `cli (aarch64-apple-darwin)`
(bare `cargo build` → `rustup run 1.93 cargo build`), but
v0.2.4's release.yml then failed on `napi (aarch64-apple-darwin)`
because `napi build` spawns a subprocess `cargo metadata` that
suffered the same macos-15 PATH discovery bug.

### Fixed

- `release.yml`: `Build napi` step now wraps the napi-rs invocation
  with `rustup run 1.93`. The wrapper ensures all `cargo`
  subprocesses spawned by `npx napi build` (most importantly the
  internal `cargo metadata` call) resolve to the 1.93 toolchain
  via rustup, not via PATH.

## [0.2.4] — 2026-05-15

Patch release. **CI fix only — no engine, rule, or public-API
changes.** Cuts a new tag because the v0.2.3 release workflow
failed on `cli (aarch64-apple-darwin)` (macos-15 runner): bare
`cargo build` resolved to `rustup-init` (the installer) instead
of the cargo shim. The napi build on the same runner succeeded
because `napi build` invokes cargo as a subprocess via Node with
a different PATH context.

### Fixed

- `release.yml`: the `Build CLI` step now uses `rustup run 1.93
  cargo build` instead of bare `cargo build`. `rustup run`
  bypasses PATH resolution and invokes the toolchain directly,
  sidestepping the macos-15 runner's PATH ordering issue where
  `cargo` resolves to `rustup-init`.

## [0.2.3] — 2026-05-14

Patch release. **CI fix only — no engine, rule, or public-API
changes.** Cuts a new tag because the v0.2.2 npm-publish dry-run
surfaced a packaging bug: the main package tarball was bundling
all 5 platform `.node` binaries (7.3 MB) instead of relying on
the `optionalDependencies` subpackages to deliver them.

### Fixed

- `crates/stryx_napi/package.json` `files` field no longer
  includes the `stryx.*.node` glob. The main npm package now
  ships only `index.js` (the napi loader that picks the right
  subpackage), `index.d.ts`, and `bin/stryx.js` (~20 KB total).
  Each end user downloads exactly one platform `.node` (~1.5 MB)
  via the matching `stryx-<platform>` optional dependency instead
  of all five.

## [0.2.2] — 2026-05-14

Patch release. **CI fix only — no engine, rule, or public-API
changes.** Cuts a new tag because the v0.2.1 release workflow
failed to produce GitHub Release artifacts, blocking the npm
publish path.

### Fixed

- `release.yml`: the `napi (aarch64-apple-darwin)` matrix entry
  was failing with `Internal Error: cargo metadata exited with
  code 1 / rustup could not choose a version of cargo to run`.
  Root cause: napi-rs CLI shells out to `cargo metadata` from a
  cwd that loses workspace `rust-toolchain.toml` discovery, and
  `dtolnay/rust-toolchain@master` was no longer setting a
  `rustup default`. Fix: explicit `rustup default 1.93` step
  after every toolchain install.
- `release.yml`: the `cli (x86_64-apple-darwin)` and
  `napi (x86_64-apple-darwin)` matrix entries were stuck queued
  indefinitely on `runs-on: macos-13` — GitHub retired the
  macos-13 Intel runner pool in April 2026. Fix: cross-compile
  `x86_64-apple-darwin` from `macos-14` (Apple Silicon) using
  `--target x86_64-apple-darwin`. macOS ships the x86 codegen
  backend by default so no extra setup is needed.

### Added

- `npx stryx scan` works locally — the napi-rs package gained a
  `bin/stryx.js` CLI shim that wraps the napi `scan()` function,
  parses `--format` / `--fail-on` / path args, prints findings in
  the same human / JSON formats as the Rust CLI, and sets the exit
  code from the maximum severity. Wires the `bin` field in
  `crates/stryx_napi/package.json`.
- `.github/workflows/npm-publish.yml` (draft, `workflow_dispatch`
  only) — manual-trigger workflow that pulls the prebuilt `.node`
  binaries from a tag's GitHub Release, runs
  `napi prepublish -t npm` to arrange platform subpackages with
  the optional-dependencies trick, and publishes to npm. Defaults
  to dry-run; a maintainer flips `dry_run=false` once `NPM_TOKEN`
  is set in repo secrets and the first-publish output looks right.

### Changed

- Docs reorganisation for that release: `CLAUDE.md` was made the
  AI-agent context file and the earlier `AGENTS.md` pointer was
  removed. This historical layout is superseded in `[Unreleased]`,
  where `AGENTS.md` becomes the canonical agent context.
- Rule-doc consistency pass: all 10 rule docs in `docs/rules/`
  now share the same 14-section template shape (the four newer
  rule docs gained `Configuration` + `Suppressing this rule`
  sections, and `Performance` was renamed to
  `Performance characteristics` for parity).
- `docs/rules/README.md` rewritten as the current v0.2.1 catalog:
  three tiers (stable cross-file v0.1, experimental cross-file
  v0.2/v0.2.1, experimental single-file v0.2, generic single-file)
  + scope legend + StepKind / ParamFlow flag counts. Previously
  listed planned-but-never-built rules.
- Rule-count corrections: README, CLAUDE, ARCHITECTURE, and the
  v0.2.0 CHANGELOG retrospective entry said "10 rules" but the
  actual v0.2.0 tag carried 11 (path-traversal missed in the
  prose). Corrected to 11.

### Fixed

- ADR 0011 status: `Proposed` → `Accepted`. Phase 2 closed at
  v0.2.1, retrospective section added (Track A shipped + extended,
  Track B over-delivered 4 of 4 vs "pick 1-2", Track C deferred
  pending rule-of-three).
- `ARCHITECTURE.md` and `CLAUDE.md` last-reviewed date bumped
  2026-05-09 → 2026-05-14.

## [0.2.1] — 2026-05-14

Patch release. **All Critical-severity rules now have cross-file
taint coverage** — SQL injection and command injection joined SSRF /
redirect-open / unvalidated-body-to-db in the cross-file tier. Plus
one precision fix surfaced by the v0.1.0 papermark OSS sweep.

`ParamFlow` gained two new reach flags
(`reaches_sql_sink_unsanitized`, `reaches_exec_sink_unsanitized`)
and one precision flag (`fetch_sink_path_pinned_only`). Pre-v0.2.1
cache entries deserialize cleanly via `#[serde(default)]` —
backwards-compatible. No breaking changes to the public CLI or JSON
output contract.

### Added

- `flow/command-injection-via-exec` slice 2 — cross-file taint
  detection. The extract pass records
  `ParamFlow::reaches_exec_sink_unsanitized` when a parameter
  reaches a Node.js `child_process` `exec` / `execSync` / `execFile`
  / `execFileSync` / `spawn` / `spawnSync` call. The run pass emits
  a Critical finding at the call site when a tainted argument flows
  into a reach-flagged parameter of a callee resolved via the
  project index. Helpers that switch internally to
  `execFile(<literal-binary>, [<args>])` (hardcoded binary, argv
  array) suppress the call-site finding. Closes the
  "all Critical-severity rules have cross-file" gap.
- `flow/sql-injection` slice 2 — cross-file taint detection. The
  extract pass simulates each exported function with one parameter
  pre-tainted and records `ParamFlow::reaches_sql_sink_unsanitized`
  when the simulation observes a raw-SQL sink (`$queryRawUnsafe`,
  `$executeRawUnsafe`, `sql.raw`, `<conn>.query`). The run pass emits
  a Critical finding at the call site when a tainted argument flows
  into a reach-flagged parameter of a callee resolved via the project
  index. Route handler → imported helper → raw-SQL chains now fire at
  the call site; helpers that switch internally to the parameterised
  tagged-template form (`prisma.$queryRaw`...``) suppress it.

### Fixed

- `flow/ssrf-via-fetch` — env-var-prefix host-pinned templates
  (`fetch(\`${process.env.X}/...?id=${body.id}\`)`) downgrade from
  High (full SSRF) to Medium (path-injection), matching the
  literal-prefix shape. The recogniser now tracks operator-controlled
  host bindings (including `??` / `||` fallback chains and via-binding
  `const base = process.env.X`). Cross-file propagation via the new
  `ParamFlow::fetch_sink_path_pinned_only` flag. Surfaced by the
  v0.1.0 papermark OSS sweep.

## [0.2.0] — 2026-05-11

Second release. Track A (cross-file slice 2 for SSRF +
redirect-open) closed, Track B over-delivered (4 of 4 new flow
rules — prompt-injection, XSS, SQL-injection, command-injection
— vs. ADR 0011's planned "pick 1-2"), plus the App Router
`searchParams.X` body-source recogniser lifting coverage across
every body-flow rule. **11 rules in the registry** (was 7 at
v0.1.0).

`StepKind` substrate grew from 14 → 17 variants × 6 trait
methods = 102 dispatch sites. Two new sink variants
(`SqlSink`, `ExecSink`, plus `LlmPromptSink` from earlier in
the cycle). No breaking changes to the public CLI / JSON output
contract.

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
- `flow/ssrf-via-fetch` three-level chain convergence — route →
  service → client → fetch. The per-param simulator now consumes
  the previous round's index, so cross-file calls already known
  to sink contribute to the chain's sink hit. Mirrors how
  `flow/unvalidated-body-to-db` converges multi-hop.
- `flow/redirect-open` slice 2 — symmetric cross-file taint
  detection for open-redirect chains. `ParamFlow::reaches_redirect_sink_unsanitized`
  + `taints_through_redirect_param` + `ConvergenceSignal::redirect_sink_params`.
  Same simulation pattern as SSRF; URL allow-list guards inside
  the callee suppress the call-site finding.
- `flow/prompt-injection` slice 1 — new flow rule catching
  request-body data flowing into an LLM provider call's prompt or
  message content. Recognises `<x>.chat.completions.create(...)`
  (OpenAI chat), `<x>.responses.create(...)` (OpenAI Responses
  API), and `<x>.messages.create(...)` (Anthropic). Inspects the
  call's first-argument object for body-tainted entries in
  `messages[].content` and `input`. Severity High; no sanitiser
  recognition (schema validation enforces shape, not prompt-
  injection safety). ADR 0011 Track B candidate #1 — Stryx's
  AI-coding-tool audience match.
- `LlmPromptSink` step variant in `steps::sinks::llm`; wired
  through `StepKind` (15 variants × 6 trait methods = 90 dispatch
  sites). Path-shape recogniser only — no import-map consultation.
- `flow/xss-via-dangerously-set-inner-html` slice 1 — new flow
  rule catching body-tainted values reaching React's
  `dangerouslySetInnerHTML={{ __html: <expr> }}` JSX attribute.
  The sink is JSX-attribute-shaped (not a call), so no new
  `StepKind` variant — the JSX walk is inline in the visitor.
  Inline sanitisers `DOMPurify.sanitize(...)` /
  `dompurify.sanitize(...)` / `sanitizeHtml(...)` /
  `sanitize_html(...)` recognised both at the `__html` site and
  at intermediate `const clean = DOMPurify.sanitize(html)`
  bindings. Severity High. ADR 0011 Track B candidate #2 —
  highest hit-rate Next.js audience match after prompt-injection.
- **`searchParams.X` recognised as a body source** in `BodySource`
  — Next.js App Router pages declare `searchParams` as a prop
  that carries URL-derived query parameters, every member of
  which is untrusted. Any member access on a bare `searchParams`
  identifier now contributes `UserInput` taint, lifting coverage
  across every body-flow rule (unvalidated-body-to-db,
  ssrf-via-fetch, redirect-open, path-traversal, prompt-injection,
  xss-via-dangerously-set-inner-html, secret-to-response) for
  App Router code. Recognition is bare-name only —
  `someObj.searchParams.X` is not treated as a source. OSS sweep
  on papermark + dub: zero regressions, zero new findings (those
  codebases use pages-style API routes, not App Router pages).
- `flow/sql-injection` slice 1 — new flow rule catching
  body-tainted values reaching a raw-SQL sink. Sinks: Prisma's
  `$queryRawUnsafe` / `$executeRawUnsafe`, Drizzle's `sql.raw`,
  and node-postgres / mysql2 `<conn>.query(<sql>, ...)` where
  `<conn>` is one of `pool` / `client` / `db` / `connection`. The
  parameterised tagged-template forms (`prisma.$queryRaw\`\``,
  `sql\`\``) are deliberately *not* sinks — they generate
  parameterised SQL and are safe by construction. Severity
  Critical (OWASP A03, CWE-89). ADR 0011 Track B candidate #4.
- `SqlSink` step variant in `steps::sinks::sql`; wired through
  `StepKind` (16 variants × 6 trait methods = 96 dispatch sites).
- `flow/command-injection-via-exec` slice 1 — new flow rule
  catching body-tainted values reaching Node.js `child_process`
  APIs (`exec` / `execSync` / `execFile` / `execFileSync` /
  `spawn` / `spawnSync`). Two callee shapes recognised:
  bare-ident (after `import { exec } from "child_process"`) and
  member calls on conventional namespace receivers (`cp`,
  `childProcess`, `child_process`). For shell-interpreted
  variants (`exec` / `execSync`) the entire first argument is the
  sink; for `execFile` / `spawn` the first argument is the binary
  path — body-controlled binary paths still permit arbitrary
  on-disk binary execution. Severity Critical (OWASP A03,
  CWE-78). ADR 0011 Track B candidate #3.
- `ExecSink` step variant in `steps::sinks::exec`; wired through
  `StepKind` — 17 variants × 6 trait methods = 102 dispatch sites.

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
and template-literal-host-injection patterns common in production
handlers.

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
