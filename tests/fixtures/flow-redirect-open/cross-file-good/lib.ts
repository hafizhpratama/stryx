// The exported helper checks the URL host against an allow-list
// before redirecting. The simulator sees the early-return guard
// and records the param as allow-listed → no cross-file finding.

import { NextResponse } from "next/server";

const ALLOWED = new Set(["app.example.com", "dashboard.example.com"]);

export function loginRedirect(target: string) {
  const parsed = new URL(target);
  if (!ALLOWED.has(parsed.host)) {
    return NextResponse.json({ error: "disallowed" }, { status: 400 });
  }
  return NextResponse.redirect(target);
}
