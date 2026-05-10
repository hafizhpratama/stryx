// Real AI-generated pattern: extract a primary-key value from the
// untrusted body via a helper, then use it as a Prisma where-clause.
// Slice 3.5 stores `id`'s shape as `Obj{id: Tainted+Bot}`. The
// local-shape-at-sink consumer reads that shape when `id` is the
// bare ident at the sink, so POST.req.param_shape ends up carrying
// a top-level `Field("id")` offset instead of just `Tainted+Bot`.

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "./db";
import { pickId } from "./helper";

export async function POST(req: NextRequest) {
  const body = await req.json();
  const id = pickId(body);
  const user = await prisma.user.update({ where: { id }, data: {} });
  return NextResponse.json(user);
}
