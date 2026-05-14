// Same shape as cross-file-bad, but the helper uses execFile with
// a hardcoded binary path and the input passed as an argv element.
// The simulator must observe that the param does NOT reach an
// unsafe-call sink, so the route's call-site finding stays silent.

import type { NextRequest } from "next/server";
import { convertVideo } from "./lib";

export async function POST(req: NextRequest) {
  const body = await req.json();
  await convertVideo(body.input);
  return new Response("ok");
}
