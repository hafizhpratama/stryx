// The exported helper uses Prisma's parameterised tagged-template
// `$queryRaw` instead of `$queryRawUnsafe`. The value is bound, not
// spliced — no SQL-injection surface, no finding.

import { prisma } from "./db";

export async function findUserBySlug(slug: string) {
  return prisma.$queryRaw`SELECT * FROM users WHERE slug = ${slug}`;
}
