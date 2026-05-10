// Symmetric to local-shape-sink: when a helper delegates through a
// chain helper and returns the local, the return-shape recorder
// reads the local's slice-3.5 shape instead of flattening to
// whole-value taint.
//
//   delegate(b) {
//     const id = pickId(b);  // slice 3.5: id : Obj{id: Tainted+Bot}
//     return id;             // return_shape: Obj{id: Tainted+Bot}
//   }
//
// Without the bare-ident return consumer, delegate's return_shape
// would collapse to Tainted+Bot — losing field info that future
// callers of delegate could otherwise use to reason about exactly
// which body fields flow back through the chain.

export function pickId(b: any) {
  return b.id;
}

export function delegate(b: any) {
  const id = pickId(b);
  return id;
}
