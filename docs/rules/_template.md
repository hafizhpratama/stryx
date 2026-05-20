# Rule Doc Template

> Copy this file when creating a new rule doc. Fill out every section.
> Empty sections are not acceptable — if a section doesn't apply, write
> "Not applicable" with one sentence explaining why.
>
> File naming: `<framework>-<rule-kebab-name>.md`
> Example: `flow-unvalidated-body-to-db.md`

---

# `<framework>/<rule-id>`

> One-line summary of what this rule catches.

## Metadata

| Field | Value |
|---|---|
| Rule ID | `framework/rule-id` |
| Status | experimental / beta / stable |
| Severity | info / low / medium / high / critical |
| Frameworks | nextjs >= 13, hono >= 4, etc. |
| Default | enabled / disabled |
| Added in | v0.x.x |

## What this rule catches

One paragraph in plain English. Imagine explaining to a junior developer
what trips this rule — no jargon, no Rust-specific language. Mention the
real-world consequence ("This is exploitable as X" / "This breaks Y").

## Why this happens

Explain the failure mode. Why do real JavaScript/TypeScript backend
projects end up with this unsafe shape? Mention framework defaults,
tutorial patterns, confusing APIs, missing runtime boundaries, or
cross-file refactors that make the issue easy to miss.

Examples of good answers:
- "Tutorial code often omits validation for brevity, then the same
  shape survives into production handlers."
- "TypeScript types describe expected data but do not validate request
  payloads at runtime."
- "The unsafe API is a convenient escape hatch, so developers reach for
  it when the typed API feels too limiting."

## Bad example

```ts
// Repro: describe source -> sink shape and stack surface

// ... the actual code that triggers the rule
```

Use a real example. If you must redact things (project names, internal
APIs), keep the structural patterns intact.

## Good example

```ts
// The fixed version. Same intent, with the safety mechanism in place.
```

The good example should pass this rule. Add tests to enforce that.

## How to fix

Explain the concrete remediation in the same terms the CLI uses. This is
not a generic "best practice" section; it is a fix guide for this rule.
State:

- the unsafe operation to remove or constrain
- the validation, allow-list, guard, parameterisation, or redaction shape
  that makes the flow safe
- where in the call path the fix should live
- what a minimal accepted fix looks like

Example:

```md
Do not pass request input directly to `fetch` as the URL. Parse it with
`new URL`, reject unsupported protocols, and allow only known hostnames
before making the outbound request.
```

## What Stryx recognizes

Document the exact shapes the current analyzer accepts as fixed. This
prevents "I fixed it, why does Stryx still fire?" confusion.

Include both positive and negative examples:

- Recognized: `schema.safeParse(value)` followed by a `success` check.
- Not recognized: a TypeScript `as SomeType` assertion.
- Recognized: host allow-list checked before `fetch`.
- Not recognized: `new URL(value)` alone.

## Taint signature

Required for flow rules; "Not applicable" for pure single-file rules.
Per [ADR 0003](../decisions/0003-cross-file-and-taint-as-core.md),
flow rules describe their detection in source/sink/sanitizer terms:

| Field | Value |
|---|---|
| Source labels | `UntrustedInput` / `Secret` / `UserId` / ... |
| Sink ids | `db.write`, `exec`, `response.body`, ... |
| Sanitizers recognized | `zod.parse`, `validator.escape`, ... |
| Scope | `CrossFile` / `SingleFile` |

If this rule contributes a *primitive* (a new source, sink, or
sanitizer) rather than a flow, describe what it adds to the taint
catalog and what existing flow rules will pick it up.

## Detection logic

A plain-English description of how the rule works. Examples for a
flow rule:

1. The taint engine produces flows where label `UntrustedInput` from
   source `nextjs/request-body` reaches sink `db.write` without a
   recognized sanitizer along the path.
2. The rule subscribes to those flows via its `taint_signature()`.
3. For each flow, emit a Finding pointing at the sink span; include
   the cross-file path so users can see where validation is missing.

For a single-file rule, describe the AST patterns directly.

Don't include Rust code here — that lives in the source file. This
section is for humans to understand what the rule is doing.

## Known false positive zones

When could this rule fire incorrectly? List them. Each item should
include guidance on suppression or fix.

- **Webhook handlers** that intentionally accept raw payloads
  → Use `// stryx-disable-next-line <rule-id> -- webhook payload`
- **Internal-only routes** behind authenticated middleware
  → If your team uses a custom validation pattern, configure
    `[rules."<rule-id>".validators]` in `stryx.toml`

If a false positive zone is common (>10% of expected fires), the rule
needs to be tightened before going beta.

## LLM escalation prompt (Layer 3)

If this rule emits UncertainZones for LLM analysis, document the prompt:

```
Given this <framework> route handler, analyze whether it validates
request body before use.

Code:
{ZONE_SOURCE}

Return JSON:
{
  "validated": boolean,
  "validator": string | null,  // name of validator if used (zod, etc.)
  "confidence": number,        // 0.0 to 1.0
  "reasoning": string          // 1-2 sentences
}
```

If this rule is purely AST-based (no LLM escalation), write "Not
applicable — this rule is fully deterministic at the AST layer."

## Performance characteristics

Rough numbers from criterion benchmarks. These help users understand
overhead.

- AST analysis: ~0.5ms per file (single rule)
- LLM escalation (if applicable): ~1.2s per zone, cached after first call

## Configuration

Any rule-specific options users can set in `stryx.toml`:

```toml
[rules."<rule-id>"]
severity = "high"        # override default
allow_validators = ["myCustomValidator"]   # additional validators to recognize
```

## Suppressing this rule

Inline:
```ts
// stryx-disable-next-line <rule-id> -- reason
```

File-level:
```ts
// stryx-disable <rule-id>
```

Project-level (`stryx.toml`):
```toml
[rules]
disabled = ["<rule-id>"]
```

## See also

- Related rules: links to similar rules
- External references: OWASP Top 10 entry, CWE ID, framework docs
- Real-world incidents: link to public post-mortems where this pattern caused issues

## History

| Version | Change |
|---|---|
| v0.1.0 | Initial implementation |
| v0.x.0 | Tightened to reduce false positives in test files |
