// Service receives the untrusted query filters and forwards them
// straight to Prisma's create() as the data argument without
// validation. Stryx's cross-file taint should follow the chain from
// controller.search → service.search → prisma.user.create.
//
// Using create() rather than findFirst() because Prisma READS
// (findUnique/findFirst/findMany/count) return Prisma-typed rows
// rather than body data and are deliberately treated as clean by
// flow/unvalidated-body-to-db; only WRITES surface findings.
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export class UsersService {
  async search(filters: any) {
    return prisma.user.create({ data: filters });
  }
}
