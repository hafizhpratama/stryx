// Leaf — the fetch sink. `doFetch`'s param flows directly to the
// URL argument with no allow-list guard.

export async function doFetch(url: string) {
  return fetch(url);
}
