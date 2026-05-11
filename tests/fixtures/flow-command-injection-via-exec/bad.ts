// Single-file command-injection fixture for
// `flow/command-injection-via-exec` slice 1. Each handler is an
// independent case the rule must flag at Critical severity.

import type { NextRequest } from "next/server";
import { exec, execSync, execFile, spawn } from "node:child_process";
import * as cp from "node:child_process";
import { promisify } from "node:util";

// CASE 1: bare `exec` with body data — canonical "run user-
// specified git ref" pattern.
export async function POST(req: NextRequest) {
  const { ref } = await req.json();
  exec(`git log --pretty=oneline ${ref}`);
  return new Response(null, { status: 204 });
}

// CASE 2: bare `execSync` with body data spliced into a template.
export async function PATCH(req: NextRequest) {
  const { path } = await req.json();
  const out = execSync(`du -sh ${path}`);
  return new Response(out);
}

// CASE 3: bare `execFile` — first arg is the binary path. Body-
// controlled binary path is arbitrary on-disk binary execution.
export async function PUT(req: NextRequest) {
  const { tool } = await req.json();
  execFile(tool, ["--help"]);
  return new Response(null, { status: 204 });
}

// CASE 4: bare `spawn` — same as execFile, the first arg is the
// binary path.
export async function DELETE(req: NextRequest) {
  const { binary } = await req.json();
  spawn(binary, []);
  return new Response(null, { status: 204 });
}

// CASE 5: `cp.exec(...)` namespace-import form with body taint.
export async function namespaceForm(req: NextRequest) {
  const { cmd } = await req.json();
  cp.exec(cmd);
  return new Response(null, { status: 204 });
}

// CASE 6: Next.js App Router searchParams reaches exec via a
// destructured binding — exercises searchParams source + exec
// sink end-to-end.
export async function GET(_req: NextRequest, {
  searchParams,
}: {
  searchParams: { tag: string };
}) {
  const tag = searchParams.tag;
  exec(`git checkout ${tag}`);
  return new Response(null, { status: 204 });
}
