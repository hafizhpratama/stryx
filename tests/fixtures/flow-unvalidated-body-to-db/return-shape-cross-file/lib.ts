// Slice 3.5 of ADR 0007 — cross-file return-shape propagation
// through variable bindings. Two-step chain:
//
//   body → passthrough(body) → result
//   result → write(result)
//
// At step 1, the caller stores the precise shape of `passthrough(body)`
// (instantiated with body's shape) under `result` via
// `taint_with_shape`. At step 2, the sink read uses that shape.
//
// Slice 3.5 is observation-only for finding *count* — the boolean
// path still fires the sink. The substrate-level effect is that
// `result` carries a richer shape than just whole-value taint.
// Behaviour-level precision lands when downstream consumers read
// `local_shape` at sink sites.

import { prisma } from "./db";

export function passthrough(input: any) {
  return input;
}

// Single-helper case — exercises the slice 3.5 wiring at one call.
export async function POST(req: any) {
  const body = await req.json();
  const result = passthrough(body);
  return prisma.user.create({ data: result });
}

// Chain case — `result` from step 1 feeds step 2. Slice 3.5 stores
// a precise shape for `result`; passthrough(result) at step 2
// reads `local_shape("result")` via `expr_to_cell` and propagates
// the chain.
export async function PUT(req: any) {
  const body = await req.json();
  const result = passthrough(body);
  const final = passthrough(result);
  return prisma.user.create({ data: final });
}
