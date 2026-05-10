// Real-world FP shape from dub admin/reset-login-attempts: a body
// field is used purely as a primary-key lookup in a Prisma where
// clause; the data block is hardcoded. The rule should still fire —
// passing an unvalidated string to a where-clause filter risks
// type-confusion attacks against the lookup itself — but at Medium
// severity, not High, so a `--fail-on=high` CI gate doesn't break
// on this lower-impact pattern.

import { NextResponse } from "next/server";
import { prisma } from "./db";

export async function POST(req: Request) {
  const { email } = await req.json();

  const user = await prisma.user.update({
    where: { email },
    data: {
      invalidLoginAttempts: 0,
      lockedAt: null,
    },
  });

  return NextResponse.json(user);
}
