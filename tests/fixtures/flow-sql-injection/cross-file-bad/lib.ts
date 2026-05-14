// The exported helper splices its parameter directly into a raw-SQL
// call. `findUserBySlug`'s parameter `slug` flows into Prisma's
// `$queryRawUnsafe` first-arg string with no parameterisation.

import { prisma } from "./db";

export async function findUserBySlug(slug: string) {
  return prisma.$queryRawUnsafe(
    `SELECT * FROM users WHERE slug = '${slug}'`,
  );
}
