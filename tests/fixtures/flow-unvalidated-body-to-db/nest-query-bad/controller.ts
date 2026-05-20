// NestJS controller — uses @Query() instead of @Body(). Pre-v0.4.0
// this case was missed because the rule hardcoded recognition to
// @Body() only. The v0.4.0 broad-adapter-pass framework/nestjs
// adapter contributes DecoratedParam matchers for @Body / @Query /
// @Param / @Headers / @Req; the rule consumes them via the active
// EnabledAdapters set, so @Query() input is now correctly pre-tainted
// and the flow to Prisma is flagged.
//
// This fixture is the proof-of-life that the v0.4.0 substrate
// actually drives detection — not just inert metadata.
import { Controller, Get, Query } from "@nestjs/common";
import { UsersService } from "./service";

@Controller("users")
export class UsersController {
  constructor(private readonly userService: UsersService) {}

  @Get("search")
  async search(@Query() filters: any) {
    return this.userService.search(filters);
  }
}
