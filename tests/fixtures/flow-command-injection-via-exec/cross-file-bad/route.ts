// AI-generated Next.js route handler. The child_process call
// happens inside `convertVideo` from `./lib`. Slice 1 cannot see
// this; slice 2 must.

import type { NextRequest } from "next/server";
import { convertVideo } from "./lib";

export async function POST(req: NextRequest) {
  const body = await req.json();
  // Direct body-tainted ident passed to a helper whose summary
  // says param `input` reaches an exec sink unsanitised.
  await convertVideo(body.input);
  return new Response("ok");
}
