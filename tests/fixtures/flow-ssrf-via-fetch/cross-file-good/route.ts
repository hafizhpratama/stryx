// Same shape as cross-file-bad, but the helper is allow-listed.
// The helper's per-param simulation must observe the URL allow-list
// guard and *not* record `reaches_fetch_sink_unsanitized`, so the
// route's call-site finding must stay silent.

import type { NextRequest } from "next/server";
import { forwardProxy } from "./lib";

export async function POST(req: NextRequest) {
  const body = await req.json();
  const upstream = await forwardProxy(body.url);
  return new Response(await upstream.text());
}
