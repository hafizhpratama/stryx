# Rule Format

How rules are structured in the Stryx codebase.

## Implementation status (as of v0.4.x)

📋 The richly-typed `Rule` trait sketch below — with
`interests()`, `taint_signature()`, `scope()`, and per-node
dispatch — is design intent. The actual shipped trait at v0.4.x
is leaner: `meta()` + `extract()` + `run()` (see
[`crates/stryx_rules/src/lib.rs`](../../crates/stryx_rules/src/lib.rs)).
`RuleMeta` carries `id`, `default_severity`, and `description`;
`extract()` contributes a per-file summary to the project index
(default no-op); `run()` returns `Vec<Finding>`. Source / sink /
sanitiser primitives moved into the `StepKind` + `TaintStep`
substrate per [ADR 0008](../decisions/0008-taint-step-trait-substrate.md);
v0.4.0 added the adapter-contributed `AstMatcher` closed-enum
substrate per [ADR 0014](../decisions/0014-adapter-substrate-api.md)
that rules query via `RuleContext::adapters`. Neither lives on the
trait surface.

The sketch below remains useful as the planning shape the trait
is evolving toward (per-node `interests` dispatch, formal
`taint_signature()`, formal `RuleScope` enum) — when rule count
makes the abstraction pay for itself.

## The `Rule` trait

Every rule implements this trait, defined in `crates/stryx_rules/src/lib.rs`.
Per [ADR 0003](../decisions/0003-cross-file-and-taint-as-core.md), the
trait carries three additional knobs over the v0.0 sketch:
`interests()`, `taint_signature()`, and `scope()`.

```rust
pub trait Rule: Send + Sync {
    /// Stable identifier, e.g. "flow/unvalidated-body-to-db".
    /// Once shipped, this NEVER changes.
    fn id(&self) -> &'static str;

    /// Default severity for findings produced by this rule.
    /// Users can override via stryx.toml.
    fn default_severity(&self) -> Severity;

    /// Frameworks this rule applies to. Empty = generic (all TS).
    fn applies_to(&self) -> &'static [Framework];

    /// Lifecycle status — affects whether the rule is enabled by default.
    fn status(&self) -> RuleStatus;

    /// Node kinds this rule wants to be dispatched for.
    /// Lets the visitor avoid invoking every rule on every node;
    /// per-rule cost stays additive, not multiplicative.
    fn interests(&self) -> &'static [NodeKind];

    /// If this rule contributes to taint analysis, return its
    /// source / sink / sanitizer signature here.
    /// Returning `None` means the rule is a pure AST/index rule.
    fn taint_signature(&self) -> Option<TaintSignature> { None }

    /// Whether this rule needs cross-file context (the project index)
    /// or can be answered from a single file.
    fn scope(&self) -> RuleScope { RuleScope::SingleFile }

    /// Run the rule against a node at one of its declared `interests()`.
    /// Emits Findings (definite) and UncertainZones (maybe — Layer 3 input).
    fn visit(&self, node: &Node, ctx: &mut RuleContext);
}
```

Rules are stateless. They receive a `RuleContext` per visit, which
gives them:

- Read access to the current node and its parents
- Read access to the project semantic index (`ctx.index()`)
- Read access to live taint state if the rule is taint-aware (`ctx.taint()`)
- Span helpers (`ctx.span()`, `ctx.line_col()`)
- Emitters (`ctx.emit_finding(...)`, `ctx.emit_uncertain(...)`)
- Configuration (`ctx.config()` — the user's per-rule settings)
- On-demand re-parse (`ctx.reparse(file_id)`) when a cross-file rule
  needs the full AST of another file

## Concrete example

`crates/stryx_rules/src/flows/unvalidated_body_to_db.rs` — the v0.1
reference flow rule:

```rust
use crate::context::RuleContext;
use crate::framework::Framework;
use crate::severity::Severity;
use crate::status::RuleStatus;
use crate::{Rule, RuleScope};
use stryx_ast::nodes::*;
use stryx_taint::{TaintLabel, TaintSignature};

pub struct UnvalidatedBodyToDb;

impl Rule for UnvalidatedBodyToDb {
    fn id(&self) -> &'static str {
        "flow/unvalidated-body-to-db"
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn applies_to(&self) -> &'static [Framework] {
        &[Framework::Nextjs, Framework::Hono, Framework::Express]
    }

    fn status(&self) -> RuleStatus {
        RuleStatus::Experimental
    }

    fn interests(&self) -> &'static [NodeKind] {
        // We subscribe to taint engine output, not raw AST nodes.
        &[]
    }

    fn taint_signature(&self) -> Option<TaintSignature> {
        Some(TaintSignature::flow(
            TaintLabel::UserInput,
            /* sink_id = */ "db.write",
        ))
    }

    fn scope(&self) -> RuleScope {
        RuleScope::CrossFile
    }

    fn visit(&self, _node: &Node, ctx: &mut RuleContext) {
        // Flow rules don't run per-node. The taint engine produces
        // flows that match this rule's signature; we shape the finding.
        for flow in ctx.taint().flows_matching(self.taint_signature().unwrap()) {
            match flow.verdict() {
                FlowVerdict::Sanitized { sanitizer } => {
                    // Validator was found along the path. No finding.
                }
                FlowVerdict::Reaches { sink_span, path } => {
                    ctx.emit_finding(Finding {
                        rule_id: self.id(),
                        severity: ctx.severity_for_rule(),
                        span: sink_span,
                        message: format!(
                            "Untrusted body reaches {} unsanitized; \
                             flow crosses {} files",
                            flow.sink().id(), path.file_count()
                        ).into(),
                        fix_hint: Some(
                            "Validate the body with zod/valibot/yup at \
                             the entry handler before passing it on".into()
                        ),
                    });
                }
                FlowVerdict::Uncertain { zone, bail_reason } => {
                    // Engine bailed (dynamic dispatch, deep recursion, etc.).
                    // Escalate to Layer 3 LLM.
                    ctx.emit_uncertain(UncertainZone {
                        rule_id: self.id(),
                        zone,
                        reason: bail_reason.into(),
                    });
                }
            }
        }
    }
}
```

The pattern: flow rules subscribe to taint engine output and shape it
into Findings or UncertainZones. The rule itself contains *no* AST
traversal — that's the engine's job. Per-rule code stays compact; the
heavy lifting is shared in `stryx_taint`.

For a *single-file* rule (e.g., a pure-AST sanitizer detector), set
`scope: SingleFile`, declare the node kinds in `interests()`, and use
`visit` to inspect each matching node directly.

## Rule docs as remediation contracts

Every shipped rule has a markdown page in `docs/rules/`. That page is
part of the public rule contract, not marketing copy. It must include:

- **How to fix** — the concrete remediation the CLI can point to.
- **What Stryx recognizes** — the exact safe shapes the analyzer accepts
  today, plus common shapes it does not accept.
- **Taint signature** — source labels, sink IDs, sanitisers/guards, and
  scope.
- **Known false positive zones** — when to suppress and when the rule
  should be tightened instead.

Do not write vague "best practice" guidance. A rule doc should answer:
"What code change makes this finding go away, and why is that change
actually safe?"

## Visitor traits

We provide several visitor traits in `stryx_ast::visit`:

- `Visit` — read-only AST walking
- `VisitMut` — mutable, for future auto-fix work (not used at v0.2.1)
- `VisitWithCtx` — visitor with implicit context threading

Most rules use `Visit`. Implement only the methods for node types you
care about; defaults walk into children. Override the default and call
the corresponding `walk_*` function manually if you need pre/post-order
control.

## Findings vs UncertainZones

The decision tree:

```
After analyzing a code region, can the AST conclude with high confidence?
├─ YES, it's a bug                  → emit Finding
├─ YES, it's safe                   → emit nothing
└─ NO, requires semantic context    → emit UncertainZone
                                      (Layer 3 will resolve)
```

UncertainZones are NOT findings. They become findings only after Layer 3
LLM escalation confirms with sufficient confidence. If LLM is disabled
(`--no-llm`), UncertainZones are reported separately as inconclusive.

**Don't emit Findings on uncertain cases.** The cost of a false positive
is much higher than the cost of running a Layer 3 escalation.

## Severity guidance

| Severity | When to use |
|---|---|
| info | Notable but not a problem ("debug endpoint exposes too much context") |
| low | Minor concern ("Missing JSDoc on auth function") |
| medium | Real issue, not directly exploitable ("Logging request body") |
| high | Likely bug or security issue ("Missing input validation") |
| critical | Severe, exploitable, or actively dangerous ("Hardcoded prod secret") |

Be conservative. A `critical` finding should mean *"this could cause an
incident in days, not weeks."* Calibration drift erodes trust.

## Performance budget per rule

The per-rule budget is the strictest of the three; the whole-pipeline and
full-scan budgets live in [ARCHITECTURE.md](../../ARCHITECTURE.md#performance-budget)
and [AGENTS.md](../../AGENTS.md).

- ≤ 1ms per file at p99 for AST analysis (this rule, in isolation)
- ≤ 100MB additional memory across the entire scan
- O(n) in AST node count where possible; O(n²) only if n is small (e.g.,
  function-local analysis)

The whole-pipeline budget for one file is ≤ 10ms p99 — that's the
combined cost of parse, walk, and *all* enabled rules. Per-rule cost
must stay well under it so dozens of rules can coexist.

If your rule exceeds these, profile with `cargo flamegraph` and optimize
or push detection to Layer 3.

## Registration

Rules must be registered in `crates/stryx_rules/src/registry.rs`:

```rust
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(flows::UnvalidatedBodyToDb),
        Box::new(flows::AuthBypassViaWrapper),
        Box::new(flows::SecretToResponse),
        // Sources, sinks, and sanitizers are not registered here —
        // they're consumed by the taint engine via their own registry
        // in stryx_taint::registry.
    ]
}
```

We use `Box<dyn Rule>` here despite the "no dyn in hot paths" rule —
this list is built once at startup, not in a hot path.

## Test fixtures

Every rule has at minimum:

```
tests/fixtures/<rule-id>/
├── bad.ts       # Triggers the rule
├── good.ts      # Does NOT trigger the rule
└── README.md    # Optional notes about the fixtures
```

Include a comment in `bad.ts` documenting the source → sink shape and
the relevant stack surface. This keeps fixture intent clear when the
implementation changes later.

## Integration tests

`tests/rules.rs`:

```rust
#[test]
fn flow_unvalidated_body_to_db() {
    let result = scan_fixture("flow/unvalidated-body-to-db/bad/");
    assert_finding!(result, "flow/unvalidated-body-to-db",
                    file: "lib/users.ts", line: 4);

    let result = scan_fixture("flow/unvalidated-body-to-db/good/");
    assert_no_findings!(result);
}
```

Cross-file fixtures use directories rather than single files because
the flow spans multiple sources (e.g., `route.ts` plus `lib/users.ts`).

The `assert_finding!` and `assert_no_findings!` macros are defined in
`tests/common/mod.rs`.

## Benchmarks

`benches/rules.rs`:

```rust
fn bench_unvalidated_body_to_db(c: &mut Criterion) {
    let fixture = "../tests/fixtures/flow/unvalidated-body-to-db/bad/";
    c.bench_function("rule:flow/unvalidated-body-to-db", |b| {
        b.iter(|| run_single_rule_on_project(black_box(fixture), &UnvalidatedBodyToDb));
    });
}
```

For cross-file rules the bench harness builds the project index once
(amortized across iterations) and only re-runs the analysis pass.

CI fails if a rule's bench regresses by more than 10% relative to the
main branch baseline.

## What you don't need to do

- You don't need to handle file I/O — `RuleContext` provides parsed AST
- You don't need to handle parallelism — `stryx_core` runs files in parallel
- You don't need to implement caching — Layer 3 caching is automatic
- You don't need to write LLM client code — emitting UncertainZones is enough

Focus on the analysis. The orchestration handles the rest.
