// Debug / health / config endpoints. Each one ships at
// least one secret straight out to a public HTTP response. Stryx
// should flag every Response.json / res.json / c.json / new Response
// call where a secret-shaped value reaches the body.

import { NextResponse } from "next/server";

// 1. Next.js App Router — bundled config dump.
export async function GET() {
  return Response.json({
    env: process.env.NODE_ENV,
    apiKey: process.env.API_KEY,
    dbUrl: process.env.DATABASE_URL,
    stripeKey: process.env.STRIPE_SECRET_KEY,
    nextAuthSecret: process.env.NEXTAUTH_SECRET,
  });
}

// 2. Indirect via local — taint propagates through a const.
export async function debugConfig() {
  const stripeKey = process.env.STRIPE_SECRET_KEY;
  return NextResponse.json({ stripeKey });
}

// 3. Express-style — `res.json` / `res.send` are sinks too.
export function pagesHandler(req: any, res: any) {
  res.json({ secret: process.env.JWT_SECRET });
}

// 4. Hardcoded credential straight at the sink.
export async function exposeStripe() {
  return Response.json({ key: "sk_test_FIXTUREFAKEKEYFIXTURE" });
}

// 5. Hono — `c.json(...)` is a sink.
export async function honoLeak(c: any) {
  return c.json({ token: process.env.GITHUB_TOKEN });
}

// 6. Web standard — `new Response(JSON.stringify(...))`.
export function webResponseLeak() {
  return new Response(JSON.stringify({ password: process.env.DB_PASSWORD }));
}
