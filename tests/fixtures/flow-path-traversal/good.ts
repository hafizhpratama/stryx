// Negative fixture for `flow/path-traversal`. These must NOT fire.

import type { NextRequest } from "next/server";
import fs from "fs";

// CASE 1: hardcoded path — no body involvement.
export async function hardcoded(_req: NextRequest) {
  const data = fs.readFileSync("./public/health.txt");
  return new Response(data);
}

// CASE 2: path resolved from env — env vars are trusted operator
// configuration, not user input.
export async function envBacked(_req: NextRequest) {
  const data = fs.readFileSync(process.env.HEALTH_FILE ?? "./public/health.txt");
  return new Response(data);
}

// CASE 3: body is read but only used for fields that don't reach
// the path — the filename is a hardcoded constant.
export async function bodyReadButFixedPath(req: NextRequest) {
  const body = await req.json();
  const _logged = body.eventType;
  const data = fs.readFileSync("./public/health.txt");
  return new Response(data);
}
