// Same intent as bad.ts, with the dynamic-code calls removed.
// Stryx accepts these shapes because there is no eval / Function
// constructor / string-payload timer call that consumes request
// data.

import type { Request, Response } from "express";
import { z } from "zod";

// 1) Numeric body fields — parse with `Number` / `parseInt`,
// reject on NaN. No eval involved.
export function updateContributions(req: Request, res: Response) {
  const preTax = Number(req.body.preTax);
  const afterTax = parseInt(req.body.afterTax, 10);
  if (!Number.isFinite(preTax) || !Number.isFinite(afterTax)) {
    return res.status(400).json({ error: "bad number" });
  }
  return res.json({ preTax, afterTax });
}

// 2) Structured input — validate with a zod schema. No Function
// constructor, no eval. The expression is interpreted by a real
// parser, not by the JS runtime.
const ExprBody = z.object({
  op: z.enum(["add", "sub"]),
  a: z.number(),
  b: z.number(),
});

export function runUserExpression(req: Request, res: Response) {
  const parsed = ExprBody.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "bad body" });
  }
  const { op, a, b } = parsed.data;
  const result = op === "add" ? a + b : a - b;
  return res.json({ result });
}

// 3) setTimeout with a function literal — the first argument is
// an arrow, not a string. Stryx recognises this as the safe
// shape and never inspects the request data closed over in the
// arrow body.
export function scheduleUserCode(req: Request, res: Response) {
  const delay = Number(req.body.delay) || 1000;
  setTimeout(() => {
    console.log("ran after", delay, "ms");
  }, delay);
  res.json({ scheduled: true });
}
