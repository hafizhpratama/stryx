// Validated counterpart: the controller parses the body with zod before
// handing it off to the service. The service still writes whatever it
// receives, but the input is provably trusted, so no finding fires.
import { Body, Controller, Post } from "@nestjs/common";
import { z } from "zod";
import { UsersService } from "./service";

const createUserSchema = z.object({
  name: z.string(),
  email: z.string().email(),
});

@Controller("users")
export class UsersController {
  constructor(private readonly userService: UsersService) {}

  @Post()
  async create(@Body() body: any) {
    const dto = createUserSchema.parse(body);
    return this.userService.create(dto);
  }
}
