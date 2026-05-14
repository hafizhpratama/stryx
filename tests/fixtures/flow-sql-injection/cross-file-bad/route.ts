// AI-generated Next.js route handler. The raw-SQL call happens
// inside `findUserBySlug` from `./lib`. Slice 1 cannot see this;
// slice 2 must.

import type { NextRequest } from "next/server";
import { findUserBySlug } from "./lib";

export async function POST(req: NextRequest) {
  const body = await req.json();
  // Direct body-tainted ident passed to a helper whose summary
  // says param `slug` reaches a SQL sink unsanitised.
  const user = await findUserBySlug(body.slug);
  return Response.json(user);
}
