// Next.js route handler. The body is parsed but never validated
// before being written to the database — Stryx should flag the prisma.user.create
// call as `flow/unvalidated-body-to-db`.

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export async function POST(req: NextRequest) {
  const body = await req.json();

  const user = await prisma.user.create({
    data: body,
  });

  return NextResponse.json(user);
}

// Variant: spread into an object literal — taint propagates through spread.
export async function PUT(req: NextRequest) {
  const payload = await req.json();

  return prisma.user.update({
    where: { id: 1 },
    data: { ...payload, updatedAt: new Date() },
  });
}

// Variant: member access on the body still tainted.
export async function PATCH(request: NextRequest) {
  const body = await request.json();

  return prisma.user.upsert({
    where: { id: 1 },
    update: { name: body.name, email: body.email },
    create: { name: body.name, email: body.email },
  });
}

// Hono variant: `c.req.json()` rather than bare `req.json()`. The taint
// must still propagate through the framework-context chain.
export async function honoCreate(c: any) {
  const body = await c.req.json();
  return db.session.create({ data: body });
}

// Drizzle variant: `db.insert(table).values(body)` is the sink shape.
export async function drizzleInsert(req: NextRequest) {
  const body = await req.json();
  return db.insert(usersTable).values(body).run();
}

// Drizzle update: `db.update(t).set(body)`.
export async function drizzleUpdate(req: NextRequest) {
  const body = await req.json();
  return db.update(usersTable).set(body).where(eq(usersTable.id, 1));
}

// NestJS @Body() variant: the framework injects body into `dto` via the
// parameter decorator; the controller writes it via a TypeORM-shape repo.
class UsersController {
  async create(@Body() dto: any) {
    return this.userRepo.save(dto);
  }
}
