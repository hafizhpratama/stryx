// Slice 3c of ADR 0006 — cross-file offset propagation. The callee
// reads its param's `.name` field at a sink, so its summary records
// `tainted_offsets: [Field("name")]`.

import { prisma } from "./db";

export async function writeName(input: any) {
  return prisma.user.update({
    where: { id: 1 },
    data: { name: input.name },
  });
}

// Caller variant 1: passes `body.user` — caller's own walk records
// `Field("user")` (the first-field on the tainted base).
export async function callerWithChain(body: any) {
  return writeName(body.user);
}

// Caller variant 2: passes bare `body` — caller's own walk records
// nothing (whole-value pass-through), so the callee's offsets are
// what populates the caller's summary.
export async function callerBare(body: any) {
  return writeName(body);
}
