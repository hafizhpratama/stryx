// AI-generated Next.js route handler. The outbound fetch happens
// inside `forwardProxy` from `./lib`. Slice 1 cannot see this;
// slice 2 must.

import type { NextRequest } from "next/server";
import { forwardProxy } from "./lib";

export async function POST(req: NextRequest) {
  const body = await req.json();
  // Direct body-tainted ident passed to a helper whose summary
  // says param `target` reaches a fetch sink unsanitized.
  const upstream = await forwardProxy(body.url);
  return new Response(await upstream.text());
}
