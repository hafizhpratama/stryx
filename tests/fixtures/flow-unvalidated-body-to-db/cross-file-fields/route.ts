// Slice 2.2 of ADR 0006 — the callee reads specific fields of its
// parameter, so its `param_shape` records `Obj{name, email}` and
// the cross-file finding's message lists those fields.

import { NextRequest, NextResponse } from "next/server";
import { saveProfile } from "./helper";

export async function POST(req: NextRequest) {
  const body = await req.json();
  const user = await saveProfile(body);
  return NextResponse.json(user);
}
