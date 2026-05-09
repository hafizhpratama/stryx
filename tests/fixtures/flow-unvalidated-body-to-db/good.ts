// Same shapes as bad.ts but with zod validation between the body source
// and the prisma sink. Stryx should report zero findings.

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db";

const CreateUserSchema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
});

export async function POST(req: NextRequest) {
  const body = await req.json();
  const data = CreateUserSchema.parse(body);

  const user = await prisma.user.create({
    data,
  });

  return NextResponse.json(user);
}

export async function PUT(req: NextRequest) {
  const payload = CreateUserSchema.parse(await req.json());

  return prisma.user.update({
    where: { id: 1 },
    data: { ...payload, updatedAt: new Date() },
  });
}

// safeParse also clears taint when the parsed result is what flows on.
export async function PATCH(request: NextRequest) {
  const result = CreateUserSchema.safeParse(await request.json());
  if (!result.success) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }

  return prisma.user.upsert({
    where: { id: 1 },
    update: result.data,
    create: result.data,
  });
}

// Hono variant — same protection, just framework-shifted.
export async function honoCreate(c: any) {
  const data = CreateUserSchema.parse(await c.req.json());
  return db.session.create({ data });
}

// Drizzle variants with zod validation between source and sink.
export async function drizzleInsert(req: NextRequest) {
  const data = CreateUserSchema.parse(await req.json());
  return db.insert(usersTable).values(data).run();
}

export async function drizzleUpdate(req: NextRequest) {
  const data = CreateUserSchema.parse(await req.json());
  return db.update(usersTable).set(data).where(eq(usersTable.id, 1));
}

// NestJS controller that pipes the @Body() through a class-validator
// pipe before the repository write. (NestJS pipes happen at the
// framework layer, not in user code, so even though we still see
// `dto`, the assumption is real validation already happened. Stryx
// can't tell — but if you go ZodValidationPipe + .parse here, taint
// clears explicitly.)
class UsersController {
  async create(@Body() dto: any) {
    const data = CreateUserSchema.parse(dto);
    return this.userRepo.save(data);
  }
}
