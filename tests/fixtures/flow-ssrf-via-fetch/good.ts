// Negative fixture for `flow/ssrf-via-fetch` — these patterns must
// NOT fire. Slice 1 recognises only hardcoded URLs; URL allow-list
// sanitiser recognition is slice 2.

import type { NextRequest } from "next/server";

// CASE 1: hardcoded URL — no body involvement.
export async function hardcodedUrl(_req: NextRequest) {
  const response = await fetch("https://api.example.com/health");
  return new Response(await response.text());
}

// CASE 2: URL string assembled from env vars and a fixed path.
export async function envBackedUrl(_req: NextRequest) {
  const base = process.env.UPSTREAM_BASE ?? "https://api.example.com";
  const response = await fetch(`${base}/health`);
  return new Response(await response.text());
}

// CASE 3: body is parsed but the URL is a fixed constant — the
// validator/parse output is irrelevant; the URL never carries body
// taint, so no finding.
export async function parsedBodyButFixedUrl(req: NextRequest) {
  const body = await req.json();
  // `body.thing` is tainted, but never reaches the URL.
  const _used = body.thing;
  const response = await fetch("https://api.example.com/health");
  return new Response(await response.text());
}
