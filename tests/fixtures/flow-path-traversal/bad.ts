// Single-file path-traversal fixture for `flow/path-traversal` slice 1.

import type { NextRequest } from "next/server";
import fs from "fs";
import fsPromises from "fs/promises";

// CASE 1: `fs.readFile` with body-supplied filename joined into a
// hardcoded prefix — template-literal concat carries body taint
// through to the sink.
export async function POST(req: NextRequest) {
  const { filename } = await req.json();
  return new Response(fs.readFileSync(`./uploads/${filename}`));
}

// CASE 2: bare body member access flowing to `fs.promises.readFile`.
export async function readFileCase(req: NextRequest) {
  const body = await req.json();
  const data = await fs.promises.readFile(body.path);
  return new Response(data);
}

// CASE 3: write sink — body content saved to a body-controlled path.
export async function writeCase(req: NextRequest) {
  const { filename, content } = await req.json();
  await fsPromises.writeFile(`./data/${filename}`, content);
  return new Response("ok");
}

// CASE 4: createReadStream with body-supplied path.
export async function streamCase(req: NextRequest) {
  const { path: userPath } = await req.json();
  const stream = fs.createReadStream(userPath);
  return new Response(stream as any);
}

// CASE 5: unlink — destructive sink, body-controlled path.
export async function unlinkCase(req: NextRequest) {
  const { target } = await req.json();
  await fsPromises.unlink(target);
  return new Response("deleted");
}
