// Slice 3.1 of ADR 0007 records `pickId`'s return_shape as
// `Obj{id: Tainted+Bot}`. Slice 3.5 substitutes the caller's
// argument shape into that return_shape at `const id = pickId(body)`,
// so the local `id` carries `Obj{id: Tainted+Bot}` in the caller.
//
// The local-shape-at-sink consumer reads that stored shape when
// `id` shows up as a bare ident at a DB sink — without it, the
// chain collapses to whole-value taint at the sink.

export function pickId(b: any) {
  return b.id;
}
