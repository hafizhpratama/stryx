// Higher-order callback fixture (audit gap #2).
//
// All these patterns are silent FNs today because the visitor sees
// the callback's parameter as a clean binding — the taint from the
// receiver (or array element) isn't propagated into the lambda's
// scope. Each case should fire `flow/unvalidated-body-to-db` after
// v0.2.11.

import type { NextRequest } from "next/server";
import { prisma } from "@/lib/db";

// CASE 1: `.then(body => sink(body))` — the canonical async pattern.
// req.json() returns a tainted Promise; the resolved value `body`
// inside the callback should inherit that taint.
export async function CASE1_promiseThen(req: NextRequest) {
  return req.json().then((body) => {
    return prisma.user.create({ data: body });
  });
}

// CASE 2: `<tainted-array>.map(item => sink(item))`. The body is an
// array of records; each `item` in the map callback is tainted.
export async function CASE2_arrayMap(req: NextRequest) {
  const records = await req.json();
  const results = records.map((item: any) =>
    prisma.user.create({ data: item }),
  );
  return Promise.all(results);
}

// CASE 3: `.forEach(item => sink(item))` — fire-and-forget array
// iteration. Same shape as CASE 2.
export async function CASE3_arrayForEach(req: NextRequest) {
  const records = await req.json();
  records.forEach((item: any) => {
    prisma.user.create({ data: item });
  });
}

// CASE 4: `.filter(item => predicate).map(item => sink(item))` —
// chained higher-order calls. The taint must flow through the filter
// (which preserves taint) into the map's callback parameter.
export async function CASE4_filterMap(req: NextRequest) {
  const records = await req.json();
  records
    .filter((r: any) => r.active)
    .forEach((r: any) => {
      prisma.user.create({ data: r });
    });
}
