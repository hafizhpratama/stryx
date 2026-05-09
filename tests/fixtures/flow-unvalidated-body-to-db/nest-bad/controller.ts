// AI-generated NestJS controller. The body is injected via @Body() and
// passed to an injected service whose `create` method writes it straight
// to Prisma without validation. Stryx should follow the cross-class flow
// (controller → service → DB) and flag the call site here.
import { Body, Controller, Post } from "@nestjs/common";
import { UsersService } from "./service";

@Controller("users")
export class UsersController {
  constructor(private readonly userService: UsersService) {}

  @Post()
  async create(@Body() body: any) {
    return this.userService.create(body);
  }
}
