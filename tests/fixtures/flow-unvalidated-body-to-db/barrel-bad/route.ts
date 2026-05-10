// Real Next.js shape: route imports from a barrel index file that
// re-exports from the actual implementation. Stryx must follow the
// re-export chain to find the sink.
import { createUser } from "./lib";

export async function POST(req: Request) {
  const body = await req.json();
  const user = await createUser(body);
  return Response.json(user);
}
