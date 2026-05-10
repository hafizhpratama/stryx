// Same shape as bad/, but the wrapper actually verifies the session
// (see ./lib.ts). Stryx should not fire on this export.

import { withAuth } from "./lib";
import { db } from "./db";

async function adminListUsers(_req: Request) {
  const users = await db.user.findMany();
  return Response.json(users);
}

export const GET = withAuth(adminListUsers);
