// Single-file SQL-injection good fixture — every handler must
// produce zero findings under `flow/sql-injection`.

import type { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { sql } from "drizzle-orm";
import { pool } from "@/lib/pg";

// GOOD 1: Prisma's parameterised tagged template — values are
// bound, not spliced. Body data is safe here.
export async function POST(req: NextRequest) {
  const { id } = await req.json();
  const user = await prisma.$queryRaw`
    SELECT id, email FROM "User" WHERE id = ${id}
  `;
  return Response.json(user);
}

// GOOD 2: prisma.$queryRawUnsafe with a string literal — no body
// data flows in. Recogniser must stay silent.
export async function staticUnsafe() {
  const all = await prisma.$queryRawUnsafe(
    `SELECT count(*) FROM "User"`,
  );
  return Response.json(all);
}

// GOOD 3: Drizzle's `sql`...`` tagged template — safe by design.
export async function PUT(req: NextRequest) {
  const { id } = await req.json();
  const result = await sql`SELECT id FROM users WHERE id = ${id}`;
  return Response.json(result);
}

// GOOD 4: node-postgres parameterised — body value passed via the
// bind array, not the SQL string. The SQL string is a literal.
export async function PATCH(req: NextRequest) {
  const { username } = await req.json();
  const rows = await pool.query(
    "SELECT * FROM users WHERE username = $1",
    [username],
  );
  return Response.json(rows);
}

// GOOD 5: pool.query with a hardcoded constant SQL — body data
// used for filtering goes through bind params, not the string.
const SELECT_ALL = "SELECT id, email FROM users LIMIT 100";
export async function GET() {
  const rows = await pool.query(SELECT_ALL);
  return Response.json(rows);
}

// GOOD 6: prisma.user.findUnique — typed Prisma API, not raw SQL.
// The recogniser must not flag the typed CRUD path even if body
// data flows in (that's the unvalidated-body-to-db rule's job).
export async function DELETE(req: NextRequest) {
  const { id } = await req.json();
  return prisma.user.findUnique({ where: { id } });
}
