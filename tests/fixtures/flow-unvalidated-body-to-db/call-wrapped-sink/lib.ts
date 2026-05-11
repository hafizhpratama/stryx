// Regression fixture for task #92 — observed in the wild on
// documenso/packages/auth/server/lib/utils/get-session.ts during
// real-world OSS validation.
//
// The outer helper passes its body-tainted parameter through an
// intermediate call-expression wrapper before reaching the
// db-writing inner helper. Pre-fix, the visitor recorded the
// finding (cross-file taint to a writing helper) but `param_shape_seen`
// stayed at Bot because `record_taint_in_arg` doesn't recurse into
// CallExpression arguments by design. The slice 2.5 invariant
// `reaches == !findings.is_empty()` fired a debug-assert panic.
//
// Post-fix, the fallback in `record_taint_in_arg` records
// whole-value root taint when an expression `expr_is_tainted_readonly`
// returns true but no structural shape was matched. The invariant
// holds; the finding still fires; the shape now contains
// `Cell { Xtaint::Tainted, Shape::Bot }`.

import { prisma } from "./db";

function passthrough(x: any): any {
  return x;
}

export async function dbWritingHelper(input: any) {
  return prisma.user.create({ data: input });
}

// Outer helper — passes its body-tainted param through a call
// wrapper before reaching the inner DB-writing helper. The
// finding emitted at `dbWritingHelper(...)` requires
// param_shape for `c` to be non-empty (slice 2.5 invariant).
export async function getSession(c: any) {
  return dbWritingHelper(passthrough(c));
}
