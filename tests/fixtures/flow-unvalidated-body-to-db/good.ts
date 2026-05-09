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
