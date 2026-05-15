// v0.2.15 fixture — reassignment propagation in non-flagship rules.
//
// Today (v0.2.14), flow/sql-injection's visitor handles
// VariableDeclarator inits (`let q = body.id`) but ignores bare
// reassignments (`q = body.id`). Both cases below are silent FNs.

import type { NextRequest } from "next/server";
import { prisma } from "./db";

// CASE 1: var starts clean, gets reassigned from body, then sinks.
// Current behaviour: q never gets marked tainted (no init taint
// recognition for bare assignments), sink doesn't fire.
export async function CASE1(req: NextRequest) {
  const body = await req.json();
  let q = "SELECT * FROM users WHERE id = '";
  q = q + body.id; // q now contains body taint, but visitor misses
  q = q + "'";
  return prisma.$queryRawUnsafe(q);
}

// CASE 2: chained reassignment — both q and r should end up tainted.
export async function CASE2(req: NextRequest) {
  const body = await req.json();
  let q;
  q = `SELECT * FROM users WHERE name = '${body.name}'`;
  let r = q; // r should inherit q's taint
  return prisma.$queryRawUnsafe(r);
}
