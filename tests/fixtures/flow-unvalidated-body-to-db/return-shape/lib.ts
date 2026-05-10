// Slice 3.1 of ADR 0007 — exercises the return-shape recorder. Each
// export here demonstrates a different return-shape pattern; the
// integration test asserts the shape recorded for each.

// Whole-value passthrough — return_shape = Tainted+Bot.
export function passthrough(b: any) {
  return b;
}

// Field selector — return_shape = Obj{id: Tainted+Bot}.
export function pickId(b: any) {
  return b.id;
}

// Object literal with two fields drawn from the param.
// return_shape = Obj{id: Tainted+Bot, data: Tainted+Bot}
// (slice 3.1 limitation: the *return-side* keys aren't separated
// from the *param-side* offsets — both `body.id` and `body.data`
// produce param-side records. Future slices add return-structure
// fidelity.)
export function shape(body: any) {
  return { id: body.id, data: body.data };
}

// No tainted return — return_shape = None.
export function noop(b: any) {
  return 42;
}

// Constant return — return_shape = None.
export function constant(b: any) {
  return "hello";
}
