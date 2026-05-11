// Negative fixture for `flow/redirect-open`. These must NOT fire.

import { NextResponse } from "next/server";
import { redirect } from "next/navigation";
import type { NextRequest } from "next/server";

// CASE 1: hardcoded path — no body involvement.
export async function hardcoded(_req: NextRequest) {
  return NextResponse.redirect("https://myapp.com/dashboard");
}

// CASE 2: env-backed redirect.
export async function envBacked(_req: NextRequest) {
  return NextResponse.redirect(process.env.RETURN_URL ?? "/dashboard");
}

// CASE 3: URL allow-list (Set.has) — same sanitiser shape as
// flow/ssrf-via-fetch.
const ALLOWED_HOSTS = new Set(["myapp.com", "app.myapp.com"]);
export async function allowListHas(req: NextRequest) {
  const { returnTo } = await req.json();
  const parsed = new URL(returnTo);
  if (!ALLOWED_HOSTS.has(parsed.host)) {
    return NextResponse.json({ error: "Host not allowed" }, { status: 403 });
  }
  return NextResponse.redirect(returnTo);
}

// CASE 4: validator-function form.
declare function isAllowedRedirectHost(host: string): boolean;
export async function validatorFn(req: NextRequest) {
  const { returnTo } = await req.json();
  const parsed = new URL(returnTo);
  if (!isAllowedRedirectHost(parsed.host)) {
    return NextResponse.json({ error: "Host not allowed" }, { status: 403 });
  }
  redirect(returnTo);
}
