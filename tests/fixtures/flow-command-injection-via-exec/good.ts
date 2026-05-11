// Single-file command-injection good fixture — every handler
// must produce zero findings under `flow/command-injection-via-exec`.

import type { NextRequest } from "next/server";
import { exec, execFile, spawn } from "node:child_process";

// GOOD 1: hardcoded command — no body taint, no flow.
export function hardcoded() {
  exec("ls -la /tmp");
}

// GOOD 2: env-var sourced command — operator-controlled, not
// attacker-controlled.
export function envSourced() {
  const cmd = process.env.STARTUP_CMD ?? "echo hello";
  exec(cmd);
}

// GOOD 3: execFile with a hardcoded binary path and body data
// in the args array — args go through argv, no shell parsing.
// First-arg taint is what the rule checks; literal binary is
// silent.
export async function POST(req: NextRequest) {
  const { ref } = await req.json();
  execFile("git", ["log", "--pretty=oneline", ref]);
  return new Response(null, { status: 204 });
}

// GOOD 4: spawn with hardcoded binary, body data in args array.
export async function PATCH(req: NextRequest) {
  const { path } = await req.json();
  spawn("du", ["-sh", path]);
  return new Response(null, { status: 204 });
}

// GOOD 5: a custom utility named `exec` from a non-child_process
// module. Body-tainted data flows in. Recogniser is name-shape
// only and will flag this — covered in the rule doc as a known
// FP zone. For the fixture we use a NON-matching name so the
// good case stays silent.
export async function customRunner(req: NextRequest) {
  const { task } = await req.json();
  // Local helper that has nothing to do with child_process.
  runTask(task);
  return new Response(null, { status: 204 });
}
function runTask(_t: string) {
  // no-op
}

// GOOD 6: body data used elsewhere but not in any exec call.
export async function bodyButNotExec(req: NextRequest) {
  const { sessionId } = await req.json();
  void sessionId;
  exec("date"); // hardcoded, no body data
  return new Response(null, { status: 204 });
}
