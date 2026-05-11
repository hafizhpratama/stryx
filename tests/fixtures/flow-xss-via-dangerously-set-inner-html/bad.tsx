// Single-file XSS fixture for `flow/xss-via-dangerously-set-inner-html`
// slice 1. Each component is an independent case the rule must flag.
//
// Body sources used: `req.body`, `req.json()`, Hono `c.req.*`, and
// Next.js App Router's `searchParams` page prop (any member access
// on `searchParams` is URL-derived → untrusted).

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

// CASE 6: Next.js App Router `searchParams.X` — canonical
// query-param-rendering pattern. URL-controlled, untrusted.
export function PageWithSearchParams({
  searchParams,
}: {
  searchParams: { html: string };
}) {
  return <div dangerouslySetInnerHTML={{ __html: searchParams.html }} />;
}

// CASE 7: searchParams chained through a binding — taint
// propagates through the assignment.
export function PageWithSearchParamsBinding({
  searchParams,
}: {
  searchParams: { content: string };
}) {
  const content = searchParams.content;
  return <main dangerouslySetInnerHTML={{ __html: content }} />;
}
