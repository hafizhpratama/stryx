// Precision-boundary fixture for task #96 — observed FP source:
// trigger.dev's admin.api.v1.orgs.$organizationId.feature-flags.ts
// using `validatePartialFeatureFlags(body)` whose return type is
// `{success: true, data: T} | {success: false, error: ...}`.
// The early-return guard on `!result.success` proves the validator
// accepted the body; Stryx must untaint `body` past the guard.
//
// Each handler pins one shape:
//   - validatorGuard      — recognised pattern (zero findings)
//   - validatorOkGuard    — same pattern with `.ok` discriminant
//   - validatorWithCast   — `body as T` wrapper at the arg site
//   - nonValidatorName    — call to a function NOT named validate*
//                           still fires the unvalidated finding
//   - missingGuard        — validator call without an early-return
//                           guard still fires
//   - unrelatedSuccess    — `!X.success` where X was bound from a
//                           non-validator call (no untainting)

import { prisma } from "./db";

declare function validatePartialFeatureFlags(
  x: unknown,
): { success: true; data: { name: string } } | { success: false; error: string };

declare function verifyToken(
  x: unknown,
): { ok: true; user: string } | { ok: false; reason: string };

declare function unrelated(
  x: unknown,
): { success: boolean; meta: unknown };

// CASE 1: canonical trigger.dev shape — `validate*(body)` followed
// by `if (!r.success) return ...`. Body must be untainted past the
// guard; the subsequent prisma.user.update should NOT fire.
export async function validatorGuard(req: Request) {
  const body = await req.json();
  const result = validatePartialFeatureFlags(body);
  if (!result.success) {
    return new Response(null, { status: 400 });
  }
  return prisma.user.update({
    where: { id: 1 },
    data: body,
  });
}

// CASE 2: `verify*` callee name + `.ok` discriminant.
export async function validatorOkGuard(req: Request) {
  const body = await req.json();
  const result = verifyToken(body);
  if (!result.ok) {
    return new Response(null, { status: 400 });
  }
  return prisma.user.update({
    where: { id: 1 },
    data: body,
  });
}

// CASE 3: `body as Type` cast inside the validator call. The
// wrapper-stripping in extract_validator_input must drill through.
export async function validatorWithCast(req: Request) {
  const body = await req.json();
  const result = validatePartialFeatureFlags(body as Record<string, unknown>);
  if (!result.success) {
    return new Response(null, { status: 400 });
  }
  return prisma.user.update({
    where: { id: 1 },
    data: body,
  });
}

// CASE 4: callee NOT matching validator pattern — `unrelated(body)`
// returns the same discriminated-union shape, but the function name
// doesn't suggest validation. The guard does NOT untaint body. The
// finding must still fire.
export async function nonValidatorName(req: Request) {
  const body = await req.json();
  const result = unrelated(body);
  if (!result.success) {
    return new Response(null, { status: 400 });
  }
  return prisma.user.update({
    where: { id: 1 },
    data: body,
  });
}

// CASE 5: validator call but no early-return guard. Without proof
// that the validator succeeded, body stays tainted. Finding fires.
export async function missingGuard(req: Request) {
  const body = await req.json();
  const _ = validatePartialFeatureFlags(body);
  return prisma.user.update({
    where: { id: 1 },
    data: body,
  });
}

// CASE 6: trigger.dev shape — the sink reads from `result.data`
// rather than the original input. Without untainting the validator
// binding itself, the conservative-propagation taint on `result`
// (since validatePartialFeatureFlags has no summary) would still
// reach the sink. With binding-untainting, `result.data` resolves
// to an untainted member access and no finding fires.
export async function validatedDataSink(req: Request) {
  const body = await req.json();
  const result = validatePartialFeatureFlags(body);
  if (!result.success) {
    return new Response(null, { status: 400 });
  }
  return prisma.user.update({
    where: { id: 1 },
    data: result.data,
  });
}
