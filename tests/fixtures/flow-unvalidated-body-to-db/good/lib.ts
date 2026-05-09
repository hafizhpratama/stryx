// Same lib.ts as bad/, but in this fixture the route validates the body
// before calling. The cross-file rule should not flag the call site.

import { prisma } from "@/lib/db";

export async function createUser(data: any) {
  return prisma.user.create({ data });
}
