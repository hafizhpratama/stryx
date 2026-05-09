// Same 3-level chain, but the body is parsed before it crosses the
// route boundary. Stryx should report zero findings.

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { signupUser } from "./service";

const Schema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
});

export async function POST(req: NextRequest) {
  const body = await req.json();
  const data = Schema.parse(body);
  const user = await signupUser(data);
  return NextResponse.json(user);
}
