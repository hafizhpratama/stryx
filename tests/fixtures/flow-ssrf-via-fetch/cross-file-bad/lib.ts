// The exported helper fetches its parameter without any allow-list
// check. `forwardProxy`'s parameter `target` flows directly to the
// `fetch(...)` URL argument.

export async function forwardProxy(target: string) {
  return fetch(target);
}
