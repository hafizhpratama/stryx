// The exported helper checks the URL host against an allow-list
// before fetching. The simulator sees the early-return guard and
// records the param as allow-listed → no cross-file finding.

const ALLOWED = new Set(["api.example.com", "internal.example.com"]);

export async function forwardProxy(target: string) {
  const parsed = new URL(target);
  if (!ALLOWED.has(parsed.host)) {
    throw new Error("disallowed host");
  }
  return fetch(target);
}
