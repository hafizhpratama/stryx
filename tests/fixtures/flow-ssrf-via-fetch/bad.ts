// Single-file SSRF fixture for `flow/ssrf-via-fetch` slice 1.
// Each handler is an independent case the rule must flag.

import type { NextRequest } from "next/server";
import axios from "axios";
import got from "got";

// CASE 1: classic body→fetch — the canonical AI-generated pattern.
export async function POST(req: NextRequest) {
  const { url } = await req.json();
  const response = await fetch(url);
  return new Response(await response.text());
}

// CASE 2: axios.get with body-tainted URL.
export async function axiosCase(req: NextRequest) {
  const body = await req.json();
  const r = await axios.get(body.target);
  return new Response(JSON.stringify(r.data));
}

// CASE 3: got with body-tainted URL.
export async function gotCase(req: NextRequest) {
  const { target } = await req.json();
  const r = await got(target);
  return new Response(r.body);
}

// CASE 4: indirect via template-literal concat — body still flows in.
// Host is itself an interpolation slot, NOT a pinned literal, so
// severity stays High (full SSRF).
export async function templateConcatCase(req: NextRequest) {
  const { host } = await req.json();
  const response = await fetch(`https://${host}/api/v1/info`);
  return new Response(await response.text());
}

// CASE 5: path-injection — host is pinned in the leading quasi
// (`https://api.example.com/.../`) and only a path segment is
// body-controlled. Severity downgrades to Medium per the tier
// split — bounded blast radius to the pinned API.
export async function pathInjectionCase(req: NextRequest) {
  const { domain } = await req.json();
  const response = await fetch(
    `https://api.example.com/v1/domains/${domain}`,
  );
  return new Response(await response.text());
}

// CASE 6: env-host path-injection — leading quasi is empty, host
// is `process.env.X`, second quasi starts with `/`. Host is
// operator-controlled, only the path/query is body-controlled.
// Severity downgrades to Medium (papermark `revalidateLinkById`
// shape — surfaced by v0.1.0 OSS sweep).
export async function envHostPathInjectionCase(req: NextRequest) {
  const body = await req.json();
  const response = await fetch(
    `${process.env.NEXTAUTH_URL}/api/revalidate?secret=s&linkId=${body.id}`,
  );
  return new Response(await response.text());
}

// CASE 7: env-host path-injection via a binding — same shape but
// the safe host is pulled into a local first, then interpolated.
// The visitor's `safe_host_bindings` map carries the recognition
// through. Severity Medium.
export async function envHostBindingPathInjectionCase(req: NextRequest) {
  const base = process.env.API_BASE ?? "https://fallback.example.com";
  const { path } = await req.json();
  const response = await fetch(`${base}/v1/items/${path}`);
  return new Response(await response.text());
}
