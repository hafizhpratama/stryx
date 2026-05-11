import { doFetch } from "./client";

export async function fetchExternal(input: string) {
  return doFetch(input);
}
