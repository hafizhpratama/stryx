import { Injectable } from "@nestjs/common";
import { prisma } from "./db";

@Injectable()
export class UsersService {
  async create(input: any) {
    return prisma.user.create({ data: input });
  }
}
