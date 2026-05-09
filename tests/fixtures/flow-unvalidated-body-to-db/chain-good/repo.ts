import { prisma } from "@/lib/db";

export async function insertUser(data: any) {
  return prisma.user.create({ data });
}
