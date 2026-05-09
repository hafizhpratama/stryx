// Validated counterparts of bad.ts. Same shape, but every secret is
// either omitted entirely, replaced with a presence boolean, or
// passed through a redactor before reaching the response.

import { NextResponse } from "next/server";

declare function redact(s: string | undefined): string;
declare function fingerprint(s: string | undefined): string;

// 1. Public env vars only — no secret-named env reads at all.
export async function GET() {
  return Response.json({
    env: process.env.NODE_ENV,
    appVersion: process.env.APP_VERSION,
    region: process.env.NEXT_PUBLIC_REGION,
    publishableKey: process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY,
  });
}

// 2. Presence check — `Boolean(...)` strips the Secret label.
export async function healthCheck() {
  return NextResponse.json({
    stripeKeyPresent: Boolean(process.env.STRIPE_SECRET_KEY),
    dbReachable: Boolean(process.env.DATABASE_URL),
  });
}

// 3. Explicit redaction.
export async function debugConfig() {
  return Response.json({
    stripeFingerprint: fingerprint(process.env.STRIPE_SECRET_KEY),
    apiKeyMasked: redact(process.env.API_KEY),
  });
}

// 4. Destructure the public bits, drop the rest.
export async function configEcho(config: any) {
  const { apiKey, secret, ...safeConfig } = config;
  return Response.json(safeConfig);
}

// 5. Hono — same redaction rule.
export async function honoSafe(c: any) {
  return c.json({ tokenPresent: Boolean(process.env.GITHUB_TOKEN) });
}
