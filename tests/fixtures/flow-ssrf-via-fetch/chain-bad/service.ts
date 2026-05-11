// Middle layer — re-exports the call into another module. Slice 2's
// per-param simulation must observe the cross-file call here and
// propagate `reaches_fetch_sink_unsanitized` from `doFetch` up to
// `fetchExternal`.

import { doFetch } from "./client";

export async function fetchExternal(input: string) {
  return doFetch(input);
}
