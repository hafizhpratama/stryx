// Same shape as bad/route.ts, but the body is parsed *before* it crosses
// the file boundary. The cross-file flow rule should stay silent.

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { createUser } from "./lib";

const Schema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
});

export async function POST(req: NextRequest) {
  const body = await req.json();
  const data = Schema.parse(body);
  const user = await createUser(data);
  return NextResponse.json(user);
}
