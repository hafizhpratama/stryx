// Branch-merge soundness fixture (the audit's #1 fix).
//
// Each case below is a real flow the visitor misses because it walks
// if/else sequentially with no scope save+union at the join. After
// the fix, every case should fire `flow/unvalidated-body-to-db`.

import type { NextRequest } from "next/server";
import { prisma } from "@/lib/db";

// CASE 1: consequent untaints, no else — skip-the-if path preserves
// tainted `payload`, but the visitor inherits the untainted state.
export async function CASE1(req: NextRequest) {
  const body = await req.json();
  let payload = body; // payload tainted
  if (Math.random() > 0.5) {
    payload = { name: "default" }; // consequent untaints payload
  }
  // Should be tainted here (skip-the-if path preserved the taint).
  return prisma.user.create({ data: payload });
}

// CASE 2: taint reintroduced in the alternate branch.
export async function CASE2(req: NextRequest) {
  const body = await req.json();
  let payload: any;
  if (Math.random() > 0.5) {
    payload = { name: "static" };
  } else {
    payload = body; // alternate taints payload
  }
  return prisma.user.create({ data: payload });
}

// CASE 3: inverse of CASE 2 — taint in consequent, safe in alternate.
// Without branch-merge, the visitor processes the alternate last and
// silently untaints payload, missing the consequent path.
export async function CASE3(req: NextRequest) {
  const body = await req.json();
  let payload: any;
  if (Math.random() > 0.5) {
    payload = body; // consequent taints payload
  } else {
    payload = { name: "static" };
  }
  return prisma.user.create({ data: payload });
}
