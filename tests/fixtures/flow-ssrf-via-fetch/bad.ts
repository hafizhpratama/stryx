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
export async function templateConcatCase(req: NextRequest) {
  const { host } = await req.json();
  const response = await fetch(`https://${host}/api/v1/info`);
  return new Response(await response.text());
}
