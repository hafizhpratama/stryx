// Single-file SQL-injection fixture for `flow/sql-injection`
// slice 1. Each handler is an independent case the rule must
// flag at Critical severity.

import type { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { sql } from "drizzle-orm";
import { pool } from "@/lib/pg";

// CASE 1: prisma.$queryRawUnsafe with template-interpolated body
// data — canonical "dynamic ORDER BY column" pattern.
export async function POST(req: NextRequest) {
  const { sortBy } = await req.json();
  const users = await prisma.$queryRawUnsafe(
    `SELECT id, email FROM "User" ORDER BY ${sortBy} ASC`,
  );
  return Response.json(users);
}

// CASE 2: prisma.$executeRawUnsafe with body data — DDL/DML form.
export async function PATCH(req: NextRequest) {
  const body = await req.json();
  await prisma.$executeRawUnsafe(
    `UPDATE "User" SET role = '${body.role}' WHERE id = ${body.id}`,
  );
  return new Response(null, { status: 204 });
}

// CASE 3: Drizzle sql.raw with body data — the escape hatch from
// the parameterised `sql`...`` tagged template.
export async function DELETE(req: NextRequest) {
  const { filter } = await req.json();
  await sql.raw(`DELETE FROM users WHERE ${filter}`);
  return new Response(null, { status: 204 });
}

// CASE 4: node-postgres `pool.query` with body-tainted template
// — string concat with attacker data, classic dynamic SQL.
export async function PUT(req: NextRequest) {
  const { username } = await req.json();
  const rows = await pool.query(
    `SELECT * FROM users WHERE username = '${username}'`,
  );
  return Response.json(rows);
}

// CASE 5: Next.js App Router searchParams reaches $queryRawUnsafe
// — exercises the new searchParams body-source recogniser.
export async function GET(_req: NextRequest, {
  searchParams,
}: {
  searchParams: { table: string };
}) {
  const rows = await prisma.$queryRawUnsafe(
    `SELECT id FROM ${searchParams.table} LIMIT 10`,
  );
  return Response.json(rows);
}
