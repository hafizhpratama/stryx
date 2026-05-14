// Same shape as cross-file-bad, but the helper uses the
// parameterised tagged-template form. The simulator must observe
// that the param does NOT reach an unsafe-call sink, so the route's
// call-site finding stays silent.

import type { NextRequest } from "next/server";
import { findUserBySlug } from "./lib";

export async function POST(req: NextRequest) {
  const body = await req.json();
  const user = await findUserBySlug(body.slug);
  return Response.json(user);
}
