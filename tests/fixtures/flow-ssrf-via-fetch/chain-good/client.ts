// Allow-list at the leaf — `doFetch` checks the host before
// calling fetch. The simulator sees the early-throw guard, so
// `reaches_fetch_sink_unsanitized` stays false. That `false`
// must propagate through `fetchExternal`'s simulation in
// service.ts on the next convergence round.

const ALLOWED = new Set(["api.example.com", "internal.example.com"]);

export async function doFetch(url: string) {
  const parsed = new URL(url);
  if (!ALLOWED.has(parsed.host)) {
    throw new Error("disallowed host");
  }
  return fetch(url);
}
