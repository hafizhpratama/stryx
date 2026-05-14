# Cross-file rules — when to use the index, the taint engine, or LLM escalation

How to choose the right abstraction when writing a rule that needs
cross-file context.

> Stryx gives rule authors three layered tools: the project semantic
> index (`stryx_index`), the inter-procedural taint engine
> (`stryx_taint`), and Layer 3 LLM escalation. Each answers a
> different *kind* of question at a different cost. Picking the wrong
> one wastes time, money, or both.

## The three tools at a glance

| Tool | Answers | p99 latency per query |
|---|---|---|
| `stryx_index` | Structural questions: where, who, what kind | ≤ 100µs |
| `stryx_taint` | Data-flow questions: does X reach Y unsanitized | ≤ 5ms per source-sink pair |
| Layer 3 LLM | Intent questions: does this code really mean X | ≤ 2s cold, ≤ 5ms cached |

A well-built flow rule typically uses all three: the index to find the
zones to inspect, the taint engine to trace flow, and the LLM only on
the small subset of zones the engine bailed on.

## Decision matrix

| Question shape | Use | Example rule |
|---|---|---|
| "Where is symbol X defined?" | Index | Resolve `withAuth` to `lib/auth.ts` |
| "Who calls function Y?" | Index | Find every route that uses `createUser` |
| "What framework is this file?" | Index | Discriminate App Router vs Pages Router |
| "Does this file import from `@/lib/db`?" | Index | Filter rule scope to DB-touching files |
| "Does an `UserInput` value flow into a DB write without zod?" | Taint | `flow/unvalidated-body-to-db` |
| "Does a `Secret` value reach a response body?" | Taint | `flow/secret-to-response` |
| "Does this wrapper actually verify auth?" | LLM | `flow/auth-bypass-via-wrapper` (with index for resolution, LLM for intent) |
| "Is this dynamic-dispatch site a sanitizer?" | LLM | Taint engine bail-out recovery |
| "Does this preprocessing constitute validation?" | LLM | Taint engine ambiguity at custom validators |

## Use the index when…

The index is the default tool. Always reach for it first. It answers
*static* questions about the project's structure: imports, exports,
call sites, file kinds, framework hints.

Examples:

```rust
// "Where does this symbol live?"
let def = ctx.index().definition_of(symbol_id)?;

// "Who calls this function across the project?"
for site in ctx.index().callers_of(symbol_id) {
    // ...
}

// "Is this a Next.js App Router file?"
match ctx.index().framework_of(file_id) {
    FrameworkHint::Nextjs { app_router: true, .. } => { /* yes */ }
    _ => return,
}

// "Does this file import zod?"
let zod = ctx.index().imports_of(file_id, "zod");
```

Cost is in microseconds. Index queries don't allocate. Use them
liberally; don't try to "save" by avoiding them.

If a rule's entire question can be answered from the index alone (no
data flow, no intent), it's a cross-file structural rule —
`scope: CrossFile` in the trait, but no `taint_signature()`.

## Use the taint engine when…

The taint engine answers questions about *labeled values flowing
through code*. It's the right tool when the question shape is "does
data with property X reach point Y, possibly with mitigations along
the way?"

Use it for:

- Untrusted input reaching dangerous sinks
- Secrets reaching response bodies, log lines, or third-party fetches
- User-controlled values reaching authorization decisions
- Filesystem reads reaching response bodies (path traversal class)

Don't use it for:

- "Where is this defined?" → use the index
- "Who calls this function?" → use the index
- "Does this function do what its name says?" → escalate to LLM
- Single-file, one-statement checks → just walk the AST

The taint engine queries the index internally and uses on-demand
re-parse for cross-file flows. You don't construct flows yourself; you
declare a `taint_signature()` on your `Rule` and the engine produces
matching flows for you to shape into Findings.

```rust
fn taint_signature(&self) -> Option<TaintSignature> {
    Some(TaintSignature::flow(
        TaintLabel::UserInput,
        /* sink_id = */ "db.write",
    ))
}

fn visit(&self, _node: &Node, ctx: &mut RuleContext) {
    for flow in ctx.taint().flows_matching(self.taint_signature().unwrap()) {
        // ... shape into Finding or UncertainZone
    }
}
```

See [`taint-engine.md`](taint-engine.md) for the full source / sink /
sanitizer model.

## Use LLM escalation when…

The LLM is the precision-recovery valve. Use it when:

1. The taint engine bails (dynamic dispatch, deep recursion, eval-shape).
   The engine emits an UncertainZone automatically; you don't write LLM
   code in your rule.
2. The question is fundamentally about *intent*, not data flow. "Does
   this wrapper authenticate?" cannot be answered by data-flow
   analysis; it requires reasoning about whether a function does what
   its name implies.
3. A custom helper sits in the middle of a flow and the engine cannot
   tell whether it sanitizes. Escalate; the LLM inspects the helper
   and returns a verdict.

Don't use it for:

- Structural questions the index already answers
- Anything you'd want a deterministic answer for
- Questions whose answer changes per scan

The Layer 3 prompt is rule-specific and lives at
`crates/stryx_llm/prompts/<category>/<rule-id>.txt`. Keep prompts
narrow: one question, structured JSON output, definitions inline. See
[`llm-escalation.md`](llm-escalation.md).

The cache key is taint-aware (see
[ADR 0005](../decisions/0005-taint-aware-cache-keys.md)) so the same
syntactic zone in a different taint context caches separately and
correctly.

## Composing the three: a worked example

`flow/unvalidated-body-to-db` uses all three tools:

```
1. Index resolves `req.json()` to the global `Request` type
   → confirms the source matches `sources/http-request-body`

2. Taint engine assigns label UserInput to the result

3. Index resolves `createUser(...)` to its definition in lib/users.ts

4. Taint engine fetches the function summary for createUser
   → label propagates through the parameter into the body

5. Taint engine sees `db.user.create({ data: input })` — sink match
   → no sanitizer found along the path

6. Rule emits Finding pointing at the sink, with cross-file path
   in the message

—or—

5'. Taint engine encounters `magicValidator(input)` — opaque helper
    → bails with reason "callee-not-resolved" or "dynamic-dispatch"

6'. UncertainZone goes to LLM with the helper's source visible
    → LLM returns { sanitized_by: "magicValidator", confidence: 0.85 }
    → engine clears the flow; no finding emitted
```

The rule code itself is short — the heavy lifting is shared in
`stryx_index`, `stryx_taint`, and the prompt template. Per-rule code
should be glue, not analysis.

## Cost guide

Rough p99 numbers on the standard 100k-LoC fixture:

| Operation | Cost |
|---|---|
| `ctx.index().definition_of(symbol)` | ≤ 50µs |
| `ctx.index().callers_of(fn)` | ≤ 200µs (fan-out dependent) |
| `ctx.index().reparse(file_id)` | ≤ 5ms cold, ≤ 2ms warm |
| Taint flow trace, single source-sink pair | ≤ 5ms cold, ≤ 1ms warm |
| Function-summary build, single fn | ≤ 2ms cold, ≤ 50µs warm |
| LLM escalation, cold | ≤ 2s |
| LLM escalation, cached | ≤ 5ms |

Index queries dominate when measured by count; LLM escalations
dominate when measured by total time. The cache layer is what makes
warm scans tractable — never skip cache instrumentation when adding a
new operation.

## Anti-patterns

These come up often enough to warn about explicitly:

### Don't reimplement taint in a single rule

If you find yourself walking the AST to track which variables hold
which values, you're rebuilding the taint engine. Stop. Add a new
`Source`, `Sink`, or `Sanitizer` to `stryx_taint` and write your rule
as a flow consumer.

### Don't hold ASTs across files

The arena is freed at step 4 of the pipeline (see
[`ast-pipeline.md`](ast-pipeline.md)). If you need cross-file AST
inspection, query the index and call `reparse(file_id)` for each file
you need; let each re-parsed arena drop before moving on. Holding ten
ASTs at once defeats the memory model.

### Don't ask the LLM open-ended security questions

"Is this code safe?" is not a Stryx prompt. Stryx prompts are narrow:
"Does label X reach sink Y unsanitized in this region?" Open-ended
prompts produce noisy verdicts and burn cache space (every variation
of the prompt requires re-asking).

### Don't put structural questions in the LLM

"Where is `withAuth` defined?" is not an LLM question — it's an index
query that takes 50µs and is deterministic. If you find yourself
asking the LLM something the index could answer, your rule design has
slipped.

### Don't escalate to LLM without a confidence threshold

Confidence < 0.7 verdicts are dropped by default. If a rule wants
lower-confidence info-level findings, document the threshold in the
rule's "LLM escalation prompt" section.

### Don't bypass the project index

You might be tempted to read another file directly (`std::fs::read_to_string`)
inside a rule. Don't. Go through `ctx.index().reparse(file_id)`. The
index handles caching, content-keying, and consistency with the rest
of the scan. A direct read bypasses all of that.

## Rule scope and the cost of cross-file analysis

Declaring `scope: CrossFile` is a real cost commitment:

- The orchestrator must build the project index before your rule runs
  (it's already built; you don't pay extra)
- Your rule may trigger on-demand re-parses of distant files
- Function summaries may need to be computed for every callee in your
  flow's reach

If your rule can answer its question from a single file, declare
`scope: SingleFile`. The orchestrator skips the index machinery for
your rule's dispatch and runs you in the per-file pass with zero
project-wide overhead.

## See also

- [`ast-pipeline.md`](ast-pipeline.md) — the 9-step pipeline; the
  index build slots between Step 4 (per-file extract) and Step 6
  (rule analysis)
- [`semantic-index.md`](semantic-index.md) — index data model and
  query API
- [`taint-engine.md`](taint-engine.md) — source / sink / sanitizer
  abstractions and propagation
- [`llm-escalation.md`](llm-escalation.md) — Layer 3 mechanics and
  prompt design
- [`rule-format.md`](rule-format.md) — the `Rule` trait, `interests()`,
  `taint_signature()`, `scope()`
- [ADR 0003](../decisions/0003-cross-file-and-taint-as-core.md) — why
  cross-file is core
- [ADR 0005](../decisions/0005-taint-aware-cache-keys.md) — why the
  cache key includes taint context
