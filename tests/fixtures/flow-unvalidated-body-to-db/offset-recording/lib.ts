// Slice 2 of ADR 0006 — exercises the param-side first-field offset
// recorder in `flow/unvalidated-body-to-db`. Every export here is an
// existing v0.1 finding shape; the test asserts which offsets each
// summary records on its parameter, *in addition to* the already-tested
// boolean.

import { prisma } from "./db";

// Member-chain reads on the param. The recorder should pick up
// Field("name") and Field("email") and de-dupe across the two
// branches.
export async function upsertNamed(body: any) {
  return prisma.user.upsert({
    where: { id: 1 },
    update: { name: body.name, email: body.email },
    create: { name: body.name, email: body.email },
  });
}

// Bare-ident param reaches the sink as a whole-value spread / shorthand.
// No member-chain is read — `tainted_offsets` should stay empty even
// though the boolean fires.
export async function createWhole(data: any) {
  return prisma.user.create({ data });
}

// Computed access with a literal string key — should record as
// Field("password") via `literal_offset_or_any`.
export async function updateLiteralKey(body: any) {
  return prisma.user.update({
    where: { id: 1 },
    data: { hash: body["password"] },
  });
}

// Computed access with a non-literal key — collapses to Any.
export async function updateAnyKey(body: any, k: string) {
  return prisma.user.update({
    where: { id: 1 },
    data: { hash: body[k] },
  });
}
