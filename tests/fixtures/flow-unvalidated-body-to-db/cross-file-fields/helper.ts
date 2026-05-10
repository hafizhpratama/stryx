// The helper reads `input.name` and `input.email` at the prisma sink.
// Its summary records `param_shape = Obj{ email: Tainted, name: Tainted }`
// (sorted by Offset::Ord at canonicalize time), which the cross-file
// finding in route.ts then surfaces as "fields: `email`, `name`".

import { prisma } from "./db";

export async function saveProfile(input: any) {
  return prisma.user.update({
    where: { id: 1 },
    data: { name: input.name, email: input.email },
  });
}
