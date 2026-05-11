// AI-generated Next.js OAuth-callback shape. The actual redirect
// happens inside `loginRedirect` from `./lib`. Slice 1 can't see
// this; slice 2 must.

import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { loginRedirect } from "./lib";

export async function POST(req: NextRequest) {
  const body = await req.json();
  return loginRedirect(body.next);
}
