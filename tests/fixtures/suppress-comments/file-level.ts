// End-to-end fixture for file-level suppression. The file-level
// marker at top silences every finding for the named rule across the
// whole file.

// stryx-disable flow/command-injection-via-exec

import type { NextRequest } from "next/server";
import { exec } from "child_process";

export async function first(req: NextRequest) {
  const { input } = await req.json();
  exec(`process ${input}`);
}

export async function second(req: NextRequest) {
  const { other } = await req.json();
  exec(`render ${other}`);
}
