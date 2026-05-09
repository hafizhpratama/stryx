// Top of a 3-level chain: route → service → repository → prisma.
// Slice 2 v0 cannot follow this (one-level only); v1's iterative
// summaries should converge and flag the call in route.ts.

import { NextRequest, NextResponse } from "next/server";
import { signupUser } from "./service";

export async function POST(req: NextRequest) {
  const body = await req.json();
  const user = await signupUser(body);
  return NextResponse.json(user);
}
