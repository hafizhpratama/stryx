// Real Next.js shape: handler imports a helper through the `@/*`
// path alias, not a relative path. Stryx must follow the alias to
// resolve the cross-file flow.
import { createUser } from "@/lib/users";

export async function POST(req: Request) {
  const body = await req.json();
  const user = await createUser(body);
  return Response.json(user);
}
