// Single-file XSS good fixture — every component must produce zero
// findings under `flow/xss-via-dangerously-set-inner-html`.

import type { NextRequest } from "next/server";
import DOMPurify from "isomorphic-dompurify";
import sanitizeHtml from "sanitize-html";

// GOOD 1: hardcoded HTML — no body taint, no flow.
export default function Hardcoded() {
  return (
    <div dangerouslySetInnerHTML={{ __html: "<b>Hello</b>" }} />
  );
}

// GOOD 2: env-var sourced HTML — operator-controlled, not
// attacker-controlled.
export function EnvSourced() {
  const banner = process.env.MARKETING_BANNER_HTML ?? "";
  return <div dangerouslySetInnerHTML={{ __html: banner }} />;
}

// GOOD 3: DOMPurify-wrapped body data — sanitiser recognised.
export async function PurifiedDomPurify(req: NextRequest) {
  const { html } = await req.json();
  const clean = DOMPurify.sanitize(html);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

// GOOD 4: DOMPurify inline at the __html site.
export async function PurifiedInline(req: NextRequest) {
  const { html } = await req.json();
  return (
    <div
      dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}
    />
  );
}

// GOOD 5: sanitize-html bare-name call — alternative sanitiser
// recognised inline at the __html site.
export async function SanitizeHtmlCase(req: NextRequest) {
  const { html } = await req.json();
  return (
    <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(html) }} />
  );
}

// GOOD 6: body data used elsewhere but not in __html.
export async function BodyButNotHtml(req: NextRequest) {
  const { sessionId } = await req.json();
  void sessionId; // logged or used as a DB key, not rendered
  return (
    <div dangerouslySetInnerHTML={{ __html: "<i>safe</i>" }} />
  );
}
