// Single-file NoSQL-injection good fixture — every handler must
// produce zero findings under `flow/nosql-injection`.
//
// Fix shape: coerce body fields to their expected scalar type
// before passing them into a MongoDB query filter, or validate the
// body with a schema (zod here) so non-scalar payloads never reach
// the query.

import type { Request, Response } from "express";
import { Body, Controller, Post } from "@nestjs/common";
import { z } from "zod";

declare const db: any;
declare const User: any;
declare const UserModel: any;

// GOOD 1: Express + mongodb driver — `String()` coercion. If the
// attacker sends `{"$gt": ""}`, it collapses to the string
// `"[object Object]"`, which matches no real login.
export function login(req: Request, res: Response) {
  db.collection("users").findOne(
    {
      login: String(req.body.login),
      password: String(req.body.password),
    },
    (err: unknown, user: unknown) => {
      res.json({ user });
    },
  );
}

// GOOD 2: zod schema rejects non-string bodies at the boundary, so
// `req.body.email` is provably a string by the time it reaches the
// filter. The rule does not see body taint on the property value
// because the validated `email` shadow is what flows in.
const EmailSchema = z.object({ email: z.string().email() });
export async function findUserByEmail(req: Request, res: Response) {
  const parsed = EmailSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid body" });
    return;
  }
  const { email } = parsed.data;
  const user = await User.findOne({ email });
  res.json({ user });
}

// GOOD 3: NestJS controller — DTO with class-validator-style
// decorators is the conventional safe shape. Here we model the
// "validated" case by coercing inside the handler; an adapter-aware
// DTO recogniser would also clear the param taint.
@Controller("users")
export class UsersController {
  @Post("lookup")
  async lookup(@Body() body: { username: string }) {
    return UserModel.findOne({ username: String(body.username) });
  }
}

// GOOD 4: `updateOne` with a coerced filter. The `$set` payload
// shape on the second argument is a separate concern (the
// `flow/unvalidated-body-to-db` rule covers it); for operator
// injection on the filter, the coercion above is the fix.
export async function updateProfile(req: Request, res: Response) {
  await db.collection("profiles").updateOne(
    { ownerId: String(req.body.ownerId) },
    { $set: { displayName: String(req.body.displayName) } },
  );
  res.status(204).end();
}

// GOOD 5: static filter — no body data on the filter at all. This
// guards against an over-eager "any `.deleteMany` is bad" rule
// shape; recogniser must stay silent when no property value is
// tainted.
export async function purgeExpired() {
  await db.collection("sessions").deleteMany({ expired: true });
}

// GOOD 6: `Array.prototype.find(callback)` — load-bearing FP-avoidance
// case. The first argument is a function, not an object literal, so
// the sink predicate's object-expression gate filters this out.
export function findInArray(req: Request) {
  const items = [{ id: 1 }, { id: 2 }];
  return items.find((it) => it.id === req.body.id);
}
