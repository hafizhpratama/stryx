// Admin route. The handler is wrapped in `withAuth`, but
// the wrapper itself is a no-op (see ./lib.ts). Stryx should follow
// the import and flag the export.

import { withAuth } from "./lib";
import { db } from "./db";

async function adminListUsers(_req: Request) {
  const users = await db.user.findMany();
  return Response.json(users);
}

export const GET = withAuth(adminListUsers);
