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

// CASE 4: canonical URL allow-list — `new URL(input)` followed by
// `!ALLOWED.has(parsed.host)` early-return. The guard proves the
// URL is allow-listed; slice 2 must untaint `url` past it.
const ALLOWED_HOSTS = new Set(["api.example.com", "cdn.example.com"]);
export async function urlAllowListHas(req: NextRequest) {
  const { url } = await req.json();
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return new Response("Invalid URL", { status: 400 });
  }
  if (!ALLOWED_HOSTS.has(parsed.host)) {
    return new Response("Host not allowed", { status: 403 });
  }
  const response = await fetch(parsed.toString());
  return new Response(await response.text());
}

// CASE 5: array allow-list with `.includes` and `.hostname`.
const ALLOWED_HOSTS_ARRAY = ["api.example.com", "cdn.example.com"];
export async function urlAllowListIncludes(req: NextRequest) {
  const { url } = await req.json();
  const parsed = new URL(url);
  if (!ALLOWED_HOSTS_ARRAY.includes(parsed.hostname)) {
    return new Response("Host not allowed", { status: 403 });
  }
  const response = await fetch(url);
  return new Response(await response.text());
}

// CASE 6: validator-function form. Recognised when the callee name
// starts with `isAllowed`/`isValid`/`validate`/`verify`/`check`.
declare function isAllowedHost(host: string): boolean;
export async function urlValidatorFunction(req: NextRequest) {
  const { url } = await req.json();
  const parsed = new URL(url);
  if (!isAllowedHost(parsed.host)) {
    return new Response("Host not allowed", { status: 403 });
  }
  const response = await fetch(url);
  return new Response(await response.text());
}

// CASE 7: throw-based guard (instead of return). `branch_returns`
// recognises both return and throw early-exits.
export async function urlAllowListThrow(req: NextRequest) {
  const { url } = await req.json();
  const parsed = new URL(url);
  if (!ALLOWED_HOSTS.has(parsed.host)) {
    throw new Error("Host not allowed");
  }
  const response = await fetch(url);
  return new Response(await response.text());
}
