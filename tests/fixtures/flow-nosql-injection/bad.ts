// Single-file NoSQL-injection fixture for `flow/nosql-injection`
// slice 1. Each handler is an independent case the rule must
// flag at High severity.
//
// Attack class — MongoDB operator injection. When the server splices
// a body field directly into a query filter, the attacker submits
// `{ "$gt": "" }` (or `$ne`, `$where`, `$regex`, …) instead of a
// scalar. The whole object becomes the filter value, defeating
// equality semantics and matching every document on the collection.

import type { Request, Response } from "express";
import { Body, Controller, Post } from "@nestjs/common";

// External shapes — kept as `any` so the fixture is self-contained;
// the rule fires on the call shape, not on imports.
declare const db: any;
declare const User: any;
declare const UserModel: any;

// CASE 1: Express + official mongodb driver — `db.collection('users').findOne`.
// Canonical NodeGoat-shape login bypass. Sending
// `{"login": {"$gt": ""}, "password": {"$gt": ""}}` returns the first
// user in the collection.
export function login(req: Request, res: Response) {
  db.collection("users").findOne(
    { login: req.body.login, password: req.body.password },
    (err: unknown, user: unknown) => {
      res.json({ user });
    },
  );
}

// CASE 2: Mongoose model — `User.findOne({...})` with body data.
// The Mongoose schema does not coerce `{$ne: null}` away; it is
// passed straight to the driver as a filter operator.
export async function findUserByEmail(req: Request, res: Response) {
  const user = await User.findOne({ email: req.body.email });
  res.json({ user });
}

// CASE 3: NestJS controller — `@Body() body` decorator pre-taints
// the parameter via the adapter substrate, then `body.username`
// flows into `UserModel.findOne` as an operator-injectable filter.
@Controller("users")
export class UsersController {
  @Post("lookup")
  async lookup(@Body() body: { username: string }) {
    return UserModel.findOne({ username: body.username });
  }
}

// CASE 4: Express + `updateOne` — filter operator injection on the
// first argument lets the attacker target rows other than the one
// they should be allowed to modify.
export async function updateProfile(req: Request, res: Response) {
  await db.collection("profiles").updateOne(
    { ownerId: req.body.ownerId },
    { $set: { displayName: req.body.displayName } },
  );
  res.status(204).end();
}

// CASE 5: deleteMany — same operator-injection class on a destructive
// path. `{"role": {"$ne": "admin"}}` deletes every non-admin row.
export async function purge(req: Request, res: Response) {
  await db.collection("sessions").deleteMany({ role: req.body.role });
  res.status(204).end();
}

// CASE 6: `find` with body data — proves the recogniser fires on
// the read path too, not only `findOne`. The object-literal gate is
// what distinguishes this from `Array.prototype.find(callback)`.
export async function search(req: Request, res: Response) {
  const results = await db.collection("posts").find({ tag: req.body.tag });
  res.json(await results.toArray());
}
