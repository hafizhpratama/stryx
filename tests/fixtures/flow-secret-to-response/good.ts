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

// 6. Bare-keyword destructure — `key` and `token` are too generic to
// taint on their own. S3 presigned-URL `key` is an object path, not a
// credential. `token` from a parse result is often a public correlation
// ID. Compound names (`apiKey`, `accessToken`) still taint.
declare function getPresignPostUrl(name: string): Promise<{ key: string; url: string }>;
export async function presignSafe(c: any, fileName: string) {
  const { key, url } = await getPresignPostUrl(fileName);
  return c.json({ key, url });
}
export async function correlationSafe(c: any, raw: string) {
  const { token } = JSON.parse(raw);
  return c.json({ token });
}

// 7. Intentional-public name prefixes (`public*`, `embed*`). Issued
// tokens that are *meant* to be returned to the client — observed
// FP source: dub's `referrals-token/route.ts` returning a Dub
// `embedTokens.referrals(...)` `publicToken` to the frontend. The
// destructure-key heuristic recognises the public-by-convention
// prefix and skips tainting.
declare function embedTokens(): Promise<{
  publicToken: string;
  embedToken: string;
  embedSecret: string;
  publicKey: string;
}>;
export async function embedIssued() {
  const { publicToken, embedToken, embedSecret, publicKey } = await embedTokens();
  return Response.json({ publicToken, embedToken, embedSecret, publicKey });
}

// 8. Body-derived destructure (validator output). When the init
// chain proves the value is parsed user input (zod `.parse(...)` /
// `.safeParse(...)`, or `JSON.parse(<body-source>)`), the
// destructure-key heuristic suppresses. Observed FP source: dub's
// `shopify/order-paid/route.ts` echoing the webhook payload's
// `checkoutToken` in a debug response message — that's user input,
// not a stored secret.
declare const schema: { parse(x: unknown): { workspaceId: string; checkoutToken: string } };
export async function webhookEcho(req: Request) {
  const rawBody = await req.text();
  const { workspaceId, checkoutToken } = schema.parse(JSON.parse(rawBody));
  return new Response(
    `[Test] workspace=${workspaceId} checkoutToken=${checkoutToken}`,
  );
}
