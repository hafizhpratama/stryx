# `flow/xss-via-dangerously-set-inner-html`

> Catches untrusted request input flowing into React's
> `dangerouslySetInnerHTML={{ __html: ... }}` JSX attribute without
> a recognised HTML sanitiser.

## Metadata

| Field | Value |
|---|---|
| Rule ID | `flow/xss-via-dangerously-set-inner-html` |
| Status | experimental |
| Severity | high |
| Frameworks | nextjs >= 13, generic React (single-file slice 1) |
| Default | enabled |
| Added in | v0.2 (Phase 2 of [ADR 0011](../decisions/0011-v01-to-v02-transition.md), Track B) |

## What this rule catches

React's `dangerouslySetInnerHTML` prop bypasses React's HTML
escaping and inserts a raw HTML string into the DOM. If the string
contains attacker-controlled data, the attacker can inject script
tags, event handlers, or HTML attributes that execute JavaScript
in the user's session (DOM-XSS).

Stryx flags JSX attributes of shape
`dangerouslySetInnerHTML={{ __html: <expr> }}` where `<expr>` is
body-tainted (request body, query, headers, or any value derived
from them) and not passed through a recognised sanitiser.

## Why this happens

`dangerouslySetInnerHTML` is often copied from examples that render a
static HTML constant. That shape compiles and runs, but the threat model
changes completely when the HTML comes from request input, URL params,
comments, profiles, or generated content.

When a feature needs "render this user-submitted Markdown" or "display
the comment with HTML formatting," the JSX attribute looks the same; the
security boundary shifts entirely.

## Bad example

```tsx
// Repro: request-controlled HTML reaches dangerouslySetInnerHTML.

import type { NextRequest } from "next/server";

export default async function CommentsPage({
  searchParams,
}: {
  searchParams: { html: string };
}) {
  const html = searchParams.html;
  return (
    <article>
      <h1>Latest comment</h1>
      <div dangerouslySetInnerHTML={{ __html: html }} />
    </article>
  );
}
```

`searchParams.html` is attacker-controlled via the URL. Any
visitor following a malicious link executes whatever JavaScript
the attacker embedded.

## Good example

```tsx
import DOMPurify from "isomorphic-dompurify";

export default async function CommentsPage({
  searchParams,
}: {
  searchParams: { html: string };
}) {
  const clean = DOMPurify.sanitize(searchParams.html);
  return (
    <article>
      <h1>Latest comment</h1>
      <div dangerouslySetInnerHTML={{ __html: clean }} />
    </article>
  );
}
```

`DOMPurify.sanitize` strips dangerous tags / attributes before
the HTML reaches the DOM. The rule recognises the sanitiser call
inline at the `__html` site and stays silent.

## How to fix

Avoid `dangerouslySetInnerHTML` for request-controlled content whenever
possible. Render text as text, or convert trusted markdown with a safe
renderer. If raw HTML is a product requirement, sanitize the HTML at the
point it enters `__html` using a maintained HTML sanitizer.

Sanitize the value you actually pass into `__html`; sanitizing a
different variable or sanitizing before later concatenation leaves the
sink unsafe.

## What Stryx recognizes

Recognized as safe:

- `DOMPurify.sanitize(value)` / `dompurify.sanitize(value)`.
- `sanitizeHtml(value)` / `sanitize_html(value)` from `sanitize-html`.
- Inline sanitizer wrapping of the exact value assigned to `__html`.

Not recognized as safe:

- Passing request input directly to `__html`.
- Trusting TypeScript types such as `SafeHtml`.
- Regex-based tag stripping.
- Sanitizing once and then concatenating more request-controlled HTML.

## Taint signature

| Field | Value |
|---|---|
| Source labels | `UserInput` (body / query / headers / searchParams) |
| Sink ids | `react.dangerouslySetInnerHTML` — the `__html` value of a `dangerouslySetInnerHTML={{ __html: <expr> }}` JSX attribute |
| Sanitizers recognized | `DOMPurify.sanitize(...)` / `dompurify.sanitize(...)` (DOMPurify, isomorphic-dompurify); `sanitizeHtml(...)` / `sanitize_html(...)` (sanitize-html). Inline at the `__html` value — wrapping the tainted expression. |
| Scope | `SingleFile` |

## Detection logic

1. Walk every `JSXAttribute`. The recogniser activates when the
   attribute name is exactly `dangerouslySetInnerHTML`.
2. The attribute's value must be an `ExpressionContainer` whose
   inner expression is an `ObjectExpression` literal with a
   property named `__html` (the canonical React shape — anything
   else is a TypeScript error at the React typings level).
3. Inspect the `__html` property's value:
   a. If it's wrapped in a recognised sanitiser call —
      `DOMPurify.sanitize(...)`, `dompurify.sanitize(...)`, bare
      `sanitizeHtml(...)`, bare `sanitize_html(...)` — drop
      taint regardless of what's inside.
   b. Otherwise, run the standard body-taint walk on the value
      expression.
4. If the value is body-tainted and not sanitiser-wrapped, emit
   a Finding at the JSX attribute span.

Slice 1 covers same-file flows. Slice 2 (deferred) extends to
cross-file via the same `ExportedFunctionSummary` consumer used
by `flow/ssrf-via-fetch` and `flow/redirect-open`.

## Known false positive zones

- **Rich-text editors with server-side sanitisation** that emit
  pre-cleaned HTML stored in the database. The DB read is treated
  as untainted by the engine, so this is correct silence. If your
  pipeline trusts a custom sanitiser not recognised here, suppress
  per line: `// stryx-disable-next-line flow/xss-via-dangerously-set-inner-html -- pre-sanitised in service layer`.
- **Server-only components rendering CMS HTML** where the HTML is
  authored by trusted editors (not end-users). The rule still
  fires; suppress with a comment if the editorial workflow is in
  place.
- **HTML emitted by a known-safe renderer** (e.g. `marked` with
  sanitiser enabled, `react-markdown`) — slice 1 doesn't recognise
  these. The cleanest fix is to feed the renderer's output through
  `DOMPurify.sanitize` anyway, which silences the rule.

## LLM escalation prompt (Layer 3)

Not applicable for slice 1 — fully deterministic AST analysis.
Future slices may emit UncertainZones when the `__html` value
comes from a function call whose sanitiser-classification cannot
be determined statically (custom renderers, dynamic config).

## Performance characteristics

- AST analysis: ~0.3ms per file (single-file slice 1; same shape
  as `flow/path-traversal`).
- Layer 3 (when enabled): not used in slice 1.

## Configuration

```toml
[rules."flow/xss-via-dangerously-set-inner-html"]
severity = "high"
```

## Suppressing this rule

Inline:
```tsx
{/* stryx-disable-next-line flow/xss-via-dangerously-set-inner-html -- reason */}
```

File-level:
```ts
// stryx-disable flow/xss-via-dangerously-set-inner-html
```

Project-level (`stryx.toml`):
```toml
[rules]
disabled = ["flow/xss-via-dangerously-set-inner-html"]
```

## See also

- OWASP A03:2021 — Injection (XSS subtype)
- CWE-79 — Improper Neutralization of Input During Web Page Generation
- React docs — `dangerouslySetInnerHTML`: "the name is intended to
  be frightening, and the only way to opt out of React's XSS
  protection is to use this attribute"

## History

| Version | Change |
|---|---|
| v0.2 | Initial single-file slice — body source → `dangerouslySetInnerHTML={{ __html: <expr> }}` JSX-attribute sink. DOMPurify + sanitize-html sanitiser recognition (inline at the `__html` site). |
