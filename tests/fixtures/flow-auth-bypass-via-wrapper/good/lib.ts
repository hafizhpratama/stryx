// The wrapper calls a recognised auth helper before invoking the
// inner handler, and short-circuits with a 401 on failure.

import { getServerSession } from "next-auth";
import { authOptions } from "./auth-options";

type Handler = (req: Request) => Promise<Response>;

export function withAuth<H extends Handler>(handler: H): Handler {
  return async (req: Request) => {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }
    return handler(req);
  };
}
