// Single-file XSS fixture for `flow/xss-via-dangerously-set-inner-html`
// slice 1. Each component is an independent case the rule must flag.
//
// All cases use body sources that `BodySource` recognises today
// (`req.body`, `req.json()`, and Hono-style `c.req.*`). Next.js
// App Router's `searchParams` prop is *also* an untrusted source
// in real apps, but adding that to `BodySource` affects every rule
// and is a separate improvement — slice 1 sticks to what's
// recognised.

import type { NextRequest } from "next/server";

// CASE 1: req.body member access (Next.js Pages API / Edge).
export async function Page1Style(req: NextRequest) {
  return (
    <div dangerouslySetInnerHTML={{ __html: req.body }} />
  );
}

// CASE 2: req.json() body directly into __html — POST-style handler
// returning an HTML fragment.
export async function CommentFragment(req: NextRequest) {
  const body = await req.json();
  return (
    <article>
      <div dangerouslySetInnerHTML={{ __html: body.html }} />
    </article>
  );
}

// CASE 3: template literal wrap doesn't save you — body data is
// still attacker-controlled past the prefix.
export async function NaiveWrap(req: NextRequest) {
  const { content } = await req.json();
  return (
    <section
      dangerouslySetInnerHTML={{ __html: `<p>${content}</p>` }}
    />
  );
}

// CASE 4: body member destructured then used — same flow, taint
// propagates through the binding.
export async function Destructured(req: NextRequest) {
  const { rich } = await req.json();
  const wrapped = rich;
  return <div dangerouslySetInnerHTML={{ __html: wrapped }} />;
}

// CASE 5: Hono-style `c.req.json()` body reaches __html.
export async function HonoStyle(c: { req: { json: () => Promise<{ html: string }> } }) {
  const { html } = await c.req.json();
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
