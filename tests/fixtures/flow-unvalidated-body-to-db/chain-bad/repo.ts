// Bottom of the chain — the actual sink. The parameter `data` reaches
// `prisma.user.create` directly, so this layer's slice-1 summary is
// `data → sink`. The fixed-point loop then propagates that fact up
// through service.ts to route.ts.

import { prisma } from "@/lib/db";

export async function insertUser(data: any) {
  return prisma.user.create({ data });
}
