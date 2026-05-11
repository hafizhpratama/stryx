// Precision-boundary fixture for the post-validation refinement
// (2026-05-11) that teaches `is_sanitizer_call` about the
// @conform-to/zod free-function `parse(input, { schema })` shape.
// Observed FP source: trigger.dev's Remix routes
// (apps/webapp/app/routes/_app.orgs.$organizationSlug.projects.
// $projectParam.env.$envParam.alerts/route.tsx and siblings).
//
// Each handler pins one shape:
//   - `conformParse`         — true sanitizer match (zero findings)
//   - `conformParseAliased`  — same with `schema: alias` key form
//   - `genericParse`         — `parse(x, base)` without `schema` key
//                              still treated as untrusted (one finding)

import { prisma } from "./db";

declare function parse<T>(
  input: unknown,
  config: { schema: unknown },
): { value?: T };
declare const userSchema: unknown;
// A custom helper that happens to be named `parse` but doesn't take
// a schema config — should NOT be recognised as a sanitizer.
declare function parseInt2(text: string, base: number): number;

// CASE 1: conform-style sanitiser, shorthand schema key.
// The rule should NOT fire — `parse(formData, { schema })` validates.
export async function conformParse(req: Request) {
  const formData = await req.formData();
  const submission = parse(formData, { schema: userSchema });
  if (!submission.value) {
    return new Response(null, { status: 400 });
  }
  const value = submission.value as { id: string };
  return prisma.user.update({
    where: { id: value.id },
    data: {},
  });
}

// CASE 2: conform-style sanitiser, schema: aliasing key.
// The rule should NOT fire — same recognition.
export async function conformParseAliased(req: Request) {
  const formData = await req.formData();
  const aliased = userSchema;
  const submission = parse(formData, { schema: aliased });
  if (!submission.value) {
    return new Response(null, { status: 400 });
  }
  const value = submission.value as { id: string };
  return prisma.user.update({
    where: { id: value.id },
    data: {},
  });
}

// CASE 3: a `parse(x, y)` call that's NOT conform-style — the second
// argument is a number, not an object with a `schema` key. The
// recogniser must reject this, and any body taint flowing through
// must still fire. (We aim a sink at the raw body to prove the rule
// still works on non-recognised parse calls.)
export async function genericParse(req: Request) {
  const body = await req.json();
  // parseInt2(body.id, 10) — generic parse, no schema config.
  // Stryx's sanitiser recogniser must NOT match this.
  const _n = parseInt2(body.id, 10);
  return prisma.user.update({
    where: { id: body.id },
    data: {},
  });
}
