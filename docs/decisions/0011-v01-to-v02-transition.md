# ADR 0011 — Phase 1 (v0.1) → Phase 2 (v0.2) transition plan

- **Date**: 2026-05-11
- **Status**: Accepted (Phase 2 closed at v0.2.1, 2026-05-14 —
  see [Retrospective](#retrospective))
- **Decider**: Hafizh Pratama
- **Supersedes**: none
- **Refines**: [ADR 0003](0003-cross-file-and-taint-as-core.md), [ADR 0008](0008-taint-step-trait-substrate.md)

## Context

Phase 1 (v0.1) was scoped as: cross-file taint substrate, three
foundational flow rules, the Next.js framework as the first
target, and an LLM-free deterministic path. The plan in
CLAUDE.md and the ADR 0003 cross-file-as-core decision committed
to three v0.1 flow rules:

- `flow/unvalidated-body-to-db`
- `flow/auth-bypass-via-wrapper`
- `flow/secret-to-response`

What actually shipped (counting commits through `fc908ec`):

**Substrate work (closed):**

- `stryx_taint` shape lattice (ADR 0006 phases 2.1a–2.5).
- `stryx_index` project semantic index (ADR 0003).
- Cross-file `ExportedFunctionSummary` consumer wiring on
  `flow/unvalidated-body-to-db`.
- Return-shape tracking (ADR 0007 slices 3.1–3.5).
- Taint-step substrate (ADR 0008 slices 8.1–8.7, fully closed).
- 14 `StepKind` variants × 6 trait methods = 84 dispatch sites.
- ADR 0009 (guard-based barriers) — drafted; partial consumer
  (early-return narrowing for `Array.includes` / `Set.has` /
  discriminated-union validator / URL allow-list).
- ADR 0010 (external library summaries) — drafted; not yet
  implemented (no consumer pressure yet).

**Rules shipped:**

| Rule | Status | Scope | Real-world TPs |
|---|---|---|---|
| `flow/unvalidated-body-to-db` | stable | Cross-file | 71 on papermark/dub |
| `flow/auth-bypass-via-wrapper` | stable | Cross-file | (no public-repo data yet) |
| `flow/secret-to-response` | stable | Single-file | (clean across OSS sample) |
| `flow/ssrf-via-fetch` | experimental | Cross-file (slice 2 in v0.2) | 4 single-file across papermark + dub; +2 new cross-file TPs in papermark (`handleDocumentCreate`/`Update`) |
| `flow/redirect-open` | experimental | Cross-file (slice 2 in v0.2) | 1 borderline single-file on dub (Jackson SAML) |
| `flow/path-traversal` | experimental | Single-file | 0 across OSS sample (cloud-blob storage dominates) |
| `flow/prompt-injection` | experimental (v0.2) | Single-file | (no public-repo data yet; AI-coding-tool audience match per ADR 0011 Track B) |
| `flow/xss-via-dangerously-set-inner-html` | experimental (v0.2) | Single-file | (no public-repo data yet; React/Next.js audience match per ADR 0011 Track B) |
| `flow/sql-injection` | experimental (v0.2) | Single-file | (no public-repo data yet; raw-SQL escape-hatch coverage that the typed-prisma rule doesn't reach) |
| `flow/command-injection-via-exec` | experimental (v0.2) | Single-file | (no public-repo data yet; covers Node.js `child_process` shell + binary-path injection) |
| `generic/hardcoded-secret` | stable | Single-file | (live in registry) |

**Real-world validation arc:**

8 production-grade Next.js repos scanned, ~28,800 TS files
total:

- **Zero-finding repos (6):** formbricks, inbox-zero, typebot,
  midday, lobe-chat, payload — all use heavy zod / TRPC / strong
  framework validation. Engine correctly produces no findings on
  these.
- **TP-heavy repos (2):** papermark (TS-cast-on-body endemic, 70
  findings), dub (6 findings — mix of admin/cron routes and
  path-injection patterns).
- **Engine-level FPs across the 8-repo arc:** 0.

**Performance:** 8,513 TS files in 2.16s on lobe-chat (~3,900
files/sec). Sub-3-second scans across the OSS sample. The
performance budget (`≤ 30s / 10k files no-LLM`) is met with ~10×
headroom.

## Decision

Declare Phase 1 done, ship v0.1.0, and open Phase 2.

### Phase 1 close-out summary

The substrate is stable. Five flow rules + one generic rule are
in the registry. ADR 0008 substrate refactor closed cleanly with
+1 new rule landing on it (`flow/redirect-open`) without
modifying any existing rule's match arms — validating the
substrate-composes invariant.

Anything further on the substrate is feature work (cross-file
slices for the experimental rules, additional rules, real
ADR 0009/0010 consumers), not v0.1 scope.

### Phase 2 (v0.2) scope

The next phase has three independent tracks:

**Track A — depth on existing rules.**

Promote the three experimental rules to stable by adding their
slice-2 cross-file extensions:

- `flow/ssrf-via-fetch` slice 2 — `ExportedFunctionSummary`
  consumer so body taint can flow through a helper module before
  reaching `fetch`. ✅ **shipped** (commits 70b41e5 / 74a2061 /
  1fa6bb5 — substrate + consumer + three-level chain
  convergence). 2 new TPs surfaced in OSS sweep
  (`handleDocumentCreate` / `handleDocumentUpdate` in papermark).
- `flow/redirect-open` slice 2 — same pattern. ✅ **shipped**
  (commit 169e2c6).
- `flow/path-traversal` slice 2 — same pattern. ⏳ remaining.
  Note: ADR 0011's OSS-sweep data showed 0 path-traversal TPs in
  the v0.1 sample (cloud-blob storage dominates), so slice 2
  here is more about symmetry than impact. Defer until a
  motivating real-world finding.

The slice-1 single-file versions are intentionally conservative
in scope. Cross-file is what makes the rules catch production
patterns that separate route handlers from service modules.

**Track B — coverage breadth.**

Phase 2 rule candidates, in priority order based on AI-output
frequency:

1. `flow/prompt-injection` — body → LLM provider call's prompt
   field. Highest AI-tool-frequency since the target audience is
   already AI-coding. Recognition is fuzzier than the other rules
   (provider-specific shapes, prompt-vs-context ambiguity).
   Slice 1 = OpenAI / Anthropic provider name match + body taint
   in the `messages[].content` / `input` fields. ✅ **shipped**
   in v0.2 — `LlmPromptSink` step variant + `flow/prompt-injection`
   rule + bad/good fixtures + bench. Single-file only; slice 2
   cross-file via `ExportedFunctionSummary` deferred until OSS
   data motivates it.

2. `flow/xss-via-dangerously-set-inner-html` — body → React
   `dangerouslySetInnerHTML` attribute. Next.js-specific. Sink
   recognition is a JSX-attribute match. ✅ **shipped** in v0.2 —
   single-file, JSX walk inline in the visitor (no `StepKind`
   sink variant since the sink isn't a call), DOMPurify +
   sanitize-html sanitiser recognition both at the `__html` site
   and at intermediate var-decl bindings.

3. `flow/command-injection-via-exec` — body → `child_process.exec`
   / `execSync` / `spawn`. Less common in serverless Next.js but
   real in self-hosted Node services. ✅ **shipped** in v0.2 —
   `ExecSink` step variant + rule recognises six method names
   across bare-ident (destructured imports) and three
   conventional namespace receivers. Severity Critical.

4. `flow/sql-injection` — body → raw SQL string via
   `prisma.$queryRaw` / direct `pg.query` / Drizzle's `sql\`\``
   tagged template. The prisma-write rule already covers Prisma's
   ORM-typed sinks; this covers the raw-SQL escape hatch.
   ✅ **shipped** in v0.2 — `SqlSink` step variant + rule
   recognises Prisma `$queryRawUnsafe` / `$executeRawUnsafe`,
   Drizzle `sql.raw`, and node-postgres / mysql2
   `<conn>.query(<sql>, ...)`. Parameterised tagged-template
   forms (`prisma.$queryRaw\`\``, `sql\`\``) are *not* sinks —
   safe by construction. Severity Critical.

Pick 1-2 of these for v0.2 based on motivating real-world data.

**Track C — substrate features pulled from drafted ADRs.**

- **ADR 0010 (external library summaries)** — implement once a
  concrete consumer rule needs it. Likely candidate: SSRF/
  redirect-open slice 2's cross-file path (resolving an imported
  helper to a TOML-described external summary).
- **ADR 0009 (guard-based barriers)** — formalise the
  guard-narrowing patterns already used ad-hoc in
  `unvalidated_body_to_db` (Array.includes, discriminant-guard)
  and `ssrf_via_fetch` (URL allow-list). Cross-rule consolidation
  if patterns proliferate.
- **ADR 0007 slice 3.6 (Shape::Fun HOF)** — real HOF feature
  implementation, building on the slice 8.7 substrate. Defer
  until `flow/auth-bypass-via-wrapper` produces a real-world FP
  on the name-regex heuristic.

### Out of scope for v0.2

- Phase 3 / 4 features (Hono / Express, type-aware analysis,
  WASM plugins) stay deferred.
- Layer 3 LLM escalation is opt-in and continues to be wired but
  not the default. The 8-repo arc validates the deterministic
  path is high-precision without it.
- `stryx_steps` standalone crate — premature; the module stays
  inside `stryx_rules`.
- DSL/declarative rule format — premature; the 30-rule threshold
  from CLAUDE.md is far off.

## Consequences

### Positive

- v0.1.0 ships with concrete validated coverage (8 repos,
  ~28,800 TS files, 0 engine-level FPs).
- The substrate work pays off cleanly: adding `flow/redirect-open`
  + `flow/path-traversal` took ~600 LOC each because the trait
  registry, source/sink dispatch, URL-allow-list sanitiser, and
  fixture/test scaffolding were already in place.
- Phase 2 has three independent tracks that can be executed in
  parallel. None block the others.

### Negative

- Three of the six flow rules are still experimental and
  single-file. Until they get cross-file slices, they catch
  fewer patterns than the cross-file rules. Mitigation: Track A
  is the v0.2 critical path.
- ADR 0009 and ADR 0010 are drafted-but-not-implemented; their
  consumers' patterns currently live as ad-hoc helpers across
  rules. Cleanup pressure rises with each rule that adds similar
  guard / external-summary logic.
- The `flow/secret-to-response` rule is single-file with its own
  conservative propagator-shaped match — not yet routed through
  the structural-propagator step. Not blocking v0.1.0 but a
  natural Phase 2 cleanup target.

### Neutral

- The 6-rule catalogue is below the 30-rule threshold for the
  rule-DSL decision. Rust-implemented rules continue.
- Public CLI / JSON output contract stays unchanged across the
  v0.1 → v0.2 transition. The Rule trait is internal and can
  evolve.

## Notes

### v0.1.0 release blockers

Before tagging v0.1.0:

- `CHANGELOG.md` covering the slice-by-slice history.
- README / docs/ link audit (cross-references between rules in
  `docs/rules/`).
- One final 8-repo sweep with a `--strict` non-zero-exit run to
  confirm the CLI contract.
- napi-rs build verification (the npm distribution path).

### Phase 2 sequencing recommendation

If we pick one Track A slice + one Track B rule for the first
v0.2 milestone, the sensible pairing is:

1. `flow/ssrf-via-fetch` slice 2 (cross-file). Highest-value
   Track A item — SSRF is the most-flagged of the new rules.
2. `flow/prompt-injection` slice 1 (single-file). Highest
   target-audience-fit Track B item.

This pairing gives v0.2 both a depth and a breadth story.

### Provenance

Status snapshot derived from `git log --oneline` between
`v0.0.1` tag and `fc908ec` (path-traversal commit). Real-world
validation numbers from `/tmp/scan-*.json` artifacts produced
during 2026-05-09 → 2026-05-11 OSS sweep.

## Retrospective

> Added 2026-05-14 at Phase 2 close-out.

Phase 2 closed with **v0.2.0** (2026-05-11) and **v0.2.1**
(2026-05-14). Outcomes vs. plan:

**Track A — depth on existing rules.** Both planned slices
shipped (`flow/ssrf-via-fetch` slice 2 + `flow/redirect-open`
slice 2). v0.2.1 extended cross-file to the two Critical-
severity rules `flow/sql-injection` and
`flow/command-injection-via-exec` as well — beyond the original
Track A scope.

**Track B — coverage breadth.** Plan called for "pick 1-2" of
the four Phase 2 rule candidates. **All four shipped**
(`flow/prompt-injection`, `flow/xss-via-dangerously-set-inner-html`,
`flow/sql-injection`, `flow/command-injection-via-exec`). The
critical injection classes (SQL + command injection) shipped
single-file in v0.2.0 and were promoted to cross-file in v0.2.1.

**Track C — substrate features.** ADRs 0009 (guard-based
barriers) and 0010 (external library summaries) remain in
`Proposed` status. The decision was rule-of-three deferred — the
existing ad-hoc guard patterns proved sufficient for v0.2's rule
set; substrate consolidation was not the bottleneck for any
Track A/B work.

**Precision fixes from OSS sweep.** The v0.1.0 papermark sweep
surfaced one FP (`revalidateLinkById` flagged as full SSRF when
the host was env-pinned). The v0.2.1 SSRF host-pinning
recogniser was added with single-file + cross-file propagation
via `ParamFlow::fetch_sink_path_pinned_only`.

**Registry size.** 7 rules at v0.1.0 → 11 rules at v0.2.1 (+4).

**ParamFlow flags.** v0.1 carried one reach flag
(`reaches_db_sink_unsanitized`). v0.2.1 carries five
(db / fetch / redirect / sql / exec, plus `fetch_sink_path_pinned_only`
for the precision tier split). All flags `#[serde(default)]` for
cache-format compat.

**StepKind growth.** 14 variants at v0.1 → 17 variants at v0.2.1
(+3: `LlmPromptSink`, `SqlSink`, `ExecSink`). 6 trait methods ×
17 variants = 102 dispatch sites.

**Phase 3 entry.** Phase 3 (Hono / Express adapters, napi-rs npm
distribution, GitHub Action, Homebrew formula) is the next plan;
captured in `README.md` Status section and `CLAUDE.md` Roadmap.
