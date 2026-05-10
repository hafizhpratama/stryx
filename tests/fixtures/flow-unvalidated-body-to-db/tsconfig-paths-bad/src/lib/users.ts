import { prisma } from "../db";

export async function createUser(input: any) {
  return prisma.user.create({ data: input });
}
