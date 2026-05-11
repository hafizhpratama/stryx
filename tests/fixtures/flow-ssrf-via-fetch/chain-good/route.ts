// Same chain shape as chain-bad, but the leaf client validates
// the host against an allow-list before calling fetch. The
// simulation must observe the early throw inside `client.doFetch`,
// drop `reaches_fetch_sink_unsanitized` there, and that absence
// must propagate up through `service.fetchExternal` so the
// route's call site stays silent.

import type { NextRequest } from "next/server";
import { fetchExternal } from "./service";

export async function POST(req: NextRequest) {
  const body = await req.json();
  const upstream = await fetchExternal(body.url);
  return new Response(await upstream.text());
}
