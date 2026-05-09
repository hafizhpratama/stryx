import { insertUser } from "./repo";

export async function signupUser(input: any) {
  return insertUser(input);
}
