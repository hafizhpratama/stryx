// Middle layer: passes the input straight through to the repository.
// No validation here.

import { insertUser } from "./repo";

export async function signupUser(input: any) {
  return insertUser(input);
}
