// Repro: untrusted request input reaches a JavaScript dynamic-code
// call (eval / Function constructor / setTimeout with string payload).
//
// Real-world shape: the NodeGoat
// (https://github.com/OWASP/NodeGoat) "contributions" handler
// passes `req.body.preTax` straight into `eval(...)` so the
// frontend can submit numeric expressions. Attacker-controlled
// expression = arbitrary code execution under the app's identity.

import type { Request, Response } from "express";

// 1) Classic `eval(req.body.X)` — OWASP A03 / CWE-95.
export function updateContributions(req: Request, res: Response) {
  const preTax = eval(req.body.preTax);
  const afterTax = eval(req.body.afterTax);
  res.json({ preTax, afterTax });
}

// 2) Function constructor — `new Function(<body>)` parses the
// string as a function body and returns a callable. The caller
// invokes it on the next line; same RCE primitive as `eval`.
export function runUserExpression(req: Request, res: Response) {
  const fn = new Function("return " + req.body.expr);
  res.json({ result: fn() });
}

// 3) setTimeout with a string payload — "implied eval". The
// runtime parses the first argument as code when it is not a
// function. The benign shape `setTimeout(() => ..., 1000)` is
// NOT flagged; only string payloads in slot 0 are.
export function scheduleUserCode(req: Request, res: Response) {
  const code = req.body.code;
  setTimeout(code, 1000);
  res.json({ scheduled: true });
}
