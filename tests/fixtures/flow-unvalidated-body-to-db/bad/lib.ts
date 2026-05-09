// The exported helper writes its parameter to Prisma without validation.
// `createUser`'s parameter `data` flows directly to `prisma.user.create`.

import { prisma } from "@/lib/db";

export async function createUser(data: any) {
  return prisma.user.create({ data });
}
