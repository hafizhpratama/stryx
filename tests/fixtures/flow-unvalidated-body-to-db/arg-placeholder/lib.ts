// Slice 2.3a of ADR 0006 — the producer emits `Arg(arg_id)` as the
// param's shape when no taint observations were recorded during
// summary extraction.

// `unused` is never read at any sink. Its summary's `param_shape`
// should be `Some(Arg("noop", 0))` rather than `None`. This is
// observation-only at the consumer side: top-level field names
// returns None for both Arg and the original None case, so the
// finding messages stay byte-identical to the pre-2.3a baseline.
export function noop(unused: any) {
  return 42;
}

// Mixed: one observed param (`body`), one unobserved (`opts`). The
// producer should emit a concrete `Tainted+Bot` for `body` and an
// `Arg` placeholder for `opts`.
import { prisma } from "./db";
export async function withOptions(body: any, opts: any) {
  return prisma.user.create({ data: body });
}
