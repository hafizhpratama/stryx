// Three-level cross-file chain: route → service → client → fetch.
// The convergence loop must propagate `reaches_fetch_sink_unsanitized`
// up through both summary layers in lock-step so the call site here
// fires.

import type { NextRequest } from "next/server";
import { fetchExternal } from "./service";

export async function POST(req: NextRequest) {
  const body = await req.json();
  const upstream = await fetchExternal(body.url);
  return new Response(await upstream.text());
}
