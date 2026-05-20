# Roadmap: Stack-Aware Scanning

This roadmap turns Stryx from "cross-file TypeScript security scanner"
into "stack-aware TypeScript backend/platform security scanner."

The end state is a CLI that detects the project stack, enables relevant
adapters, and reports security findings using the user's runtime,
framework, database, validation, auth, and LLM vocabulary.

## Current baseline

Stryx already has the hard parts:

- Rust CLI
- oxc parser
- cross-file project index
- taint-flow rules
- suppressions
- human and JSON output
- JS/TS file collection
- rules for SQL injection, command injection, SSRF, open redirects,
  path traversal, prompt injection, secrets, auth bypass, and
  unvalidated body-to-DB flows

The missing layer is a formal project profile and adapter registry.

## Phase 0: Design lock

Deliverables:

- [x] Product CLI spec: `docs/product/stack-aware-cli.md`
- [x] Project profile architecture: `docs/architecture/project-profile.md`
- [x] Stack adapter architecture: `docs/architecture/stack-adapters.md`
- [x] Stack catalog: `docs/stacks/README.md`
- [x] ADR: `docs/decisions/0013-stack-aware-project-profiles.md`

Acceptance criteria:

- The product boundary is explicit: backend/platform security, not React
  quality.
- The implementation path is adapter-based, not framework-specific rule
  forks.

## Phase 1: ProjectProfile skeleton

Goal: detect and report the stack without changing rule behavior.

Likely files:

- `crates/stryx_index/src/profile.rs`
- `crates/stryx_index/src/lib.rs`
- `crates/stryx_cli/src/lib.rs`
- `crates/stryx_reporter/src/lib.rs`

Tasks:

- Add `ProjectProfile`, `Detected<T>`, `Evidence`, and hint enums.
- Add cheap evidence collection from:
  - `package.json`
  - lockfiles
  - `tsconfig.json` / `jsconfig.json`
  - config files such as `bunfig.toml`, `wrangler.toml`, `vercel.json`
- Include the profile in JSON output.
- Print a compact profile summary in human output.
- Add fixture tests for profile detection.

Acceptance criteria:

- `stryx scan --format=json` includes `profile`.
- Running on a Bun/Hono fixture reports Bun and Hono.
- No existing rule finding changes.

## Phase 2: CLI detection UX

Goal: make detection visible and pleasant.

Tasks:

- Add interactive detection lines for local TTY runs.
- Add no-prompt deterministic mode for CI.
- Add `--profile` to print profile evidence and exit.
- Add `--no-profile` as a debugging escape hatch.
- Add `--all` / `--project <path>` planning for workspaces.

Acceptance criteria:

- Local runs show language/runtime/framework/database/validation/auth/LLM
  detection before findings.
- CI runs do not prompt.
- `--profile --format=json` is stable enough for tests and bug reports.

## Phase 3: AdapterRegistry substrate

Goal: introduce adapters while preserving current behavior.

Likely files:

- `crates/stryx_rules/src/adapters/mod.rs`
- `crates/stryx_rules/src/adapters/registry.rs`
- `crates/stryx_rules/src/steps/mod.rs`
- existing flow rule files under `crates/stryx_rules/src/flows/`

Tasks:

- Add `StackAdapter` trait and `AdapterRegistry`.
- Register generic adapters that mirror current source/sink behavior.
- Pass enabled adapters through `RuleContext` or `ProjectIndex`.
- Move existing source/sink/sanitiser recognizers behind adapter-like
  helpers without changing output.
- Add tests asserting current fixtures still pass.

Acceptance criteria:

- All current tests pass with no finding count changes.
- Adapter IDs appear in debug/profile output.
- New adapters can be added without editing every flow rule.

## Phase 4: Broad adapter pass

Goal: every P0 and P1 adapter in the stack catalog ships in one
release, so any user installing Stryx gets real findings regardless
of stack — no first-class stack and no second-class stack.

Adapters shipped (all P0/P1 from `docs/stacks/README.md`):

- Runtimes: `node`, `bun`
- Frameworks: `next-backend`, `hono`, `express`, `fastify`, `nestjs`
- Data layers: `prisma`, `drizzle`, `pg`, `mysql2`, `mongoose`
- Validators: `zod`, `valibot`, `yup`, `joi`, `ajv`, `class-validator`
- Auth: `better-auth`, `auth-js`, `clerk`
- LLM SDKs: `openai`, `anthropic`

Scoping rules per adapter:

- Recognize the 3-5 most common idioms per role
  (source / sink / sanitiser / guard).
- Document remaining gaps in the rule doc's "What Stryx recognizes"
  section.
- Add at least one fixture per (rule × adapter) intersection that
  meaningfully exists.

Acceptance criteria:

- All 11 existing rules fire correctly when adapters contribute
  new source / sink / sanitiser shapes for previously-unsupported
  stacks.
- A NestJS controller hitting a Prisma write fires
  `flow/unvalidated-body-to-db`; a Hono handler hitting a Drizzle
  raw-SQL call fires `flow/sql-injection`; an Express handler hitting
  a `child_process.exec` fires `flow/command-injection-via-exec`.
- No rule semantics change in this phase — adapter content only.

CLI ergonomics shipped alongside:

- `npx @hafizhpratama/stryx` (no subcommand) runs `scan .` by
  default — the most common case is the shortest command.
- Explicit subcommands (`scan`, `version`, `rules`) keep working
  for scripts and CI configs that pin them.
- `--help` continues to list all subcommands; the default-scan
  shortcut is documented under the no-args invocation line.

## Phase 5: P2 adapter follow-ups

Goal: fill in the long tail as real codebases surface needs.

Adapters: `deno`, `cloudflare-workers`, `elysia`, `oak`, `kysely`,
`knex`, `bun-sqlite`, `bun-sql`, `arktype`, `typebox`,
`supabase-auth`, `lucia`, `vercel-ai-sdk`, `langchain`.

Each ships as a patch release when a user reports a real project
where it's missing. Same scoping rules as Phase 4 (3-5 idioms per
role, gaps documented, one fixture per meaningful intersection).

## Phase 6: Report polish

Goal: make output dense, terse, and acceptable in CI without
sacrificing local-run readability.

Tasks:

- Group findings by severity and rule.
- Print representative findings by default.
- Add `--verbose` for all findings.
- Write full diagnostics to a temp JSON file for local runs.
- Add a profile block to the top of human reports.
- Add `Read more` links to rule fix guides.
- Ensure each rule group has one concise fix hint.
- Add elapsed time and file counts.

Acceptance criteria:

- Default output is short enough for a large repo.
- Users can see exactly which stack adapters were enabled.
- Every visible rule links to a doc section explaining how to fix it and
  what Stryx recognizes as fixed.
- Full detail is available without rerunning expensive analysis.

## Phase 7: GitHub Action and annotations

Goal: catch issues on every PR.

Tasks:

- Add GitHub Action wrapper.
- Emit GitHub annotations.
- Add sticky PR comment mode.
- Support `--diff <base>` once changed-file scanning is implemented.
- Include profile summary in PR comment.

Acceptance criteria:

- PRs can fail on `--fail-on high`.
- Inline annotations point to exact source lines.
- The PR comment explains the detected stack and enabled adapters.

## Phase 8: Score

Goal: add score only after finding quality is trusted.

Tasks:

- Define score formula.
- Cap score based on critical/high findings.
- Include score in human, JSON, and action output.
- Add config to disable score.

Acceptance criteria:

- Critical findings cap score at 49.
- High findings cap score at 74.
- Score never hides serious findings.

## Risks

False positives:

- Mitigation: adapters must include negative fixtures and confidence
  thresholds.

Framework churn:

- Mitigation: keep adapters small and evidence-based; avoid hard-coding
  broad "best practice" opinions.

Rule duplication:

- Mitigation: generic rules own semantics; adapters only contribute
  facts.

Slow scans:

- Mitigation: no network calls, no LLM calls, and no dependency installs
  during detection.

Product confusion:

- Mitigation: consistently say "TypeScript backend/platform security,"
  not "code quality" or "general-purpose linter."

## Release shape

Suggested release train:

- `v0.3.0`: profile JSON + human profile block, no behavior changes
  (shipped)
- `v0.4.0`: adapter substrate + broad adapter pass across all P0/P1
  stacks (every P0/P1 framework, runtime, data layer, validator,
  auth, and LLM SDK adapter ships in one release)
- `v0.5.0`: P2 adapter follow-ups as user demand surfaces +
  report polish (grouped findings, representative locations,
  full-diagnostics dump, `--diff <base>`)
- `v0.6.0`: GitHub Action with sticky PR comment + annotations
- `v0.7.0`: score (0–100, severity-capped) and surface controls
  (`cli` / `prComment` / `score` / `ciFailure` routing)
- `v1.0.0`: stable profile schema, stable adapter IDs, CI-ready
  defaults
