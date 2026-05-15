// End-to-end fixture for line-level suppression comments. Each
// section is a real rule violation that would normally fire — the
// suppression marker on the preceding line should silence it.

import type { NextRequest } from "next/server";
import { exec } from "child_process";

// CASE 1: matching rule-id — should be suppressed.
export async function suppressed(req: NextRequest) {
  const { input } = await req.json();
  // stryx-disable-next-line flow/command-injection-via-exec -- whitelisted by ops
  exec(`process ${input}`);
}

// CASE 2: non-matching rule-id — should still fire.
export async function notSuppressed(req: NextRequest) {
  const { input } = await req.json();
  // stryx-disable-next-line flow/ssrf-via-fetch -- wrong rule id
  exec(`process ${input}`);
}
