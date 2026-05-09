// AI-generated Next.js route handler. The DB write happens inside
// `createUser` from `./lib`. Slice 1 cannot see this; slice 2 must.

import { NextRequest, NextResponse } from "next/server";
import { createUser } from "./lib";

export async function POST(req: NextRequest) {
  const body = await req.json();
  const user = await createUser(body);
  return NextResponse.json(user);
}
