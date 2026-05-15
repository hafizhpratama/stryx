// v0.2.14 precision fixture — destructuring projection.
//
// `const { a, b } = body` should bind `a` and `b` at body's
// projected offsets, not whole-value. After v0.2.13's per-field
// sanitisation + v0.2.14's projection: `const { safe, unsafe } =
// body` with `body.safe` sanitised gives `safe` clean and `unsafe`
// tainted — no over-approximation.

import { z } from "zod";
import type { NextRequest } from "next/server";
import { prisma } from "@/lib/db";

const IdSchema = z.string().uuid();

// CASE 1 (should NOT fire — precision win in v0.2.14):
// body.id is sanitised; destructuring binds `id` to body.id's
// Cell, which is Clean. The DB call uses only `id`.
export async function CASE1_destructured_sanitised(req: NextRequest) {
  const body = await req.json();
  IdSchema.parse(body.id);
  const { id } = body; // id ← body.id (Clean)
  return prisma.user.findFirst({ where: { id } });
}

// CASE 2 (SHOULD fire — control case):
// body.id sanitised but the destructure pulls body.name too;
// `name` inherits tainted (no sanitisation on body.name).
export async function CASE2_destructured_mixed(req: NextRequest) {
  const body = await req.json();
  IdSchema.parse(body.id);
  const { id, name } = body;
  return prisma.user.create({
    data: {
      id, // clean
      name, // tainted — fires here
    },
  });
}

// CASE 3 (SHOULD fire — control case for "no sanitisation":
// pure whole-value taint through destructure).
export async function CASE3_destructured_unsanitised(req: NextRequest) {
  const body = await req.json();
  const { email } = body; // body.email inherits whole-value taint
  return prisma.user.create({ data: { email } });
}
