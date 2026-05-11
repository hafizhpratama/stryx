// Same shape as cross-file-bad, but the helper is allow-listed.
// The simulator must observe the URL allow-list guard inside
// `loginRedirect` and drop `reaches_redirect_sink_unsanitized`,
// keeping the route's call site silent.

import type { NextRequest } from "next/server";
import { loginRedirect } from "./lib";

export async function POST(req: NextRequest) {
  const body = await req.json();
  return loginRedirect(body.next);
}
