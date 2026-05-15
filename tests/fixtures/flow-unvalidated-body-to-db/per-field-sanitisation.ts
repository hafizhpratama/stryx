// v0.2.13 precision fixture — per-field sanitisation write-through.
//
// `Schema.parse(body.x)` validates `body.x` (throws on bad input).
// After v0.2.13 the visitor records that `body.x` is Clean in
// `body`'s Cell, so subsequent reads of `body.x` no longer report
// tainted. Reads of OTHER fields of `body` still report tainted —
// the whole-value taint inherits to every unobserved field.

import { z } from "zod";
import type { NextRequest } from "next/server";
import { prisma } from "@/lib/db";

const IdSchema = z.string().uuid();

// CASE 1 (should NOT fire — precision win in v0.2.13):
// `body.id` is validated by Schema.parse; the subsequent DB call
// uses ONLY body.id, which is clean post-validation.
export async function CASE1_validated_field_only(req: NextRequest) {
  const body = await req.json();
  IdSchema.parse(body.id); // throws if not a UUID — body.id now clean
  return prisma.user.findFirst({ where: { id: body.id } });
}

// CASE 2 (SHOULD fire — control case):
// `body.id` is validated, but the DB call ALSO uses `body.name`
// which was NOT validated. The whole-value taint inherits to
// unobserved fields, so body.name is still tainted.
export async function CASE2_validated_one_field_uses_another(req: NextRequest) {
  const body = await req.json();
  IdSchema.parse(body.id); // body.id clean; body.name still tainted
  return prisma.user.create({
    data: {
      id: body.id, // clean
      name: body.name, // tainted — this is what fires
    },
  });
}

// CASE 3 (should NOT fire — precision win):
// `body.user.email` deep-path sanitisation. Subsequent read of
// `body.user.email` is clean.
export async function CASE3_nested_path_sanitisation(req: NextRequest) {
  const body = await req.json();
  z.string().email().parse(body.user.email);
  return prisma.user.create({
    data: {
      email: body.user.email, // clean by deep-path carve-out
    },
  });
}
