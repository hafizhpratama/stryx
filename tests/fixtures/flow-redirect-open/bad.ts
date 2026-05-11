// Single-file open-redirect fixture for `flow/redirect-open` slice 1.

import { NextResponse } from "next/server";
import { redirect } from "next/navigation";
import type { NextRequest } from "next/server";

// CASE 1: classic NextResponse.redirect with body-supplied URL.
export async function POST(req: NextRequest) {
  const { returnTo } = await req.json();
  return NextResponse.redirect(returnTo);
}

// CASE 2: bare `redirect` from `next/navigation`.
export async function bareRedirectCase(req: NextRequest) {
  const { url } = await req.json();
  redirect(url);
}

// CASE 3: Express-style `res.redirect(url)`.
export function expressRedirect(req: any, res: any) {
  const { destination } = req.body;
  res.redirect(destination);
}

// CASE 4: Response.redirect (Web platform).
export async function webResponseRedirect(req: Request) {
  const { target } = await req.json();
  return Response.redirect(target);
}
