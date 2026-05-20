# Stack Catalog

This catalog lists the TypeScript backend/platform stacks Stryx should
detect and the adapter facts each stack should contribute.

The catalog is not a promise to implement every stack at once. It is the
shared vocabulary for project profiles, adapters, config, docs, and
reporting.

## Boundaries

In scope:

- server runtimes
- API frameworks
- route handlers and middleware
- database/query layers
- validators
- auth/session libraries
- LLM SDKs
- deployment/runtime surfaces

Out of scope:

- React component structure
- React hooks
- client rendering performance
- accessibility linting
- Tailwind/style quality
- bundle-size style advice

## Runtime adapters

| Adapter ID | Detection evidence | Contributions |
|---|---|---|
| `runtime/node` | `engines.node`, Node built-in imports, package scripts | `process.env`, `child_process`, `fs`, HTTP request shapes |
| `runtime/bun` | `bun.lock`, `bunfig.toml`, `packageManager: bun`, `Bun.*`, imports from `bun` | `Bun.serve` sources, `Bun.spawn` sinks, `Bun.file`/`Bun.write` path sinks, Bun SQL sinks |
| `runtime/deno` | `deno.json`, imports from `jsr:`, `Deno.*` | `Deno.serve` sources, `Deno.Command` sinks, `Deno.readTextFile` path sinks |
| `runtime/cloudflare-workers` | `wrangler.toml`, `@cloudflare/workers-types`, `export default { fetch }` | request sources, environment binding sources, KV/R2/D1 sinks |
| `runtime/vercel-edge` | `runtime = "edge"`, `export const runtime = "edge"` | Web `Request` sources, edge runtime constraints |

## Framework adapters

| Adapter ID | Detection evidence | Contributions |
|---|---|---|
| `framework/next-backend` | `next` dependency, `app/api/**/route.ts`, server actions, middleware | `Request`/`NextRequest` sources, `NextResponse.redirect`, route params, cookies |
| `framework/hono` | `hono` dependency/imports, `new Hono()`, `c.req.*` | `c.req.json/query/param` sources, `c.json`, `c.redirect`, middleware guards |
| `framework/express` | `express` dependency/imports, `express()`, `app.get/post` | `req.body/query/params` sources, `res.json`, `res.redirect`, middleware guards |
| `framework/fastify` | `fastify` dependency/imports, `fastify()` | `request.body/query/params` sources, `reply.send`, hooks/guards |
| `framework/nestjs` | `@nestjs/*`, decorators like `@Controller`, `@Post` | DTO/body sources, guards, injected service cross-file flow |
| `framework/elysia` | `elysia` dependency/imports, `new Elysia()` | Bun-first route sources, schema guards, response sinks |
| `framework/oak` | `oak` imports, Deno route handlers | Deno request sources and redirect/response sinks |

## Data-layer adapters

| Adapter ID | Detection evidence | Contributions |
|---|---|---|
| `data/prisma` | `@prisma/client`, `prisma.schema`, Prisma client usage | DB write sinks, unsafe raw SQL sinks, safe typed query paths |
| `data/drizzle` | `drizzle-orm`, `drizzle.config.*`, `sql.raw` | DB write sinks, raw SQL sinks, safe query-builder paths |
| `data/kysely` | `kysely` dependency/imports | DB write sinks, raw SQL sinks, parameterized SQL paths |
| `data/knex` | `knex` dependency/imports | DB write sinks, raw SQL sinks |
| `data/pg` | `pg` dependency/imports, `Pool`, `Client` | `.query` raw SQL sinks, parameterized query recognition |
| `data/mysql2` | `mysql2` dependency/imports | `.query`/`.execute` SQL sinks, parameterized query recognition |
| `data/bun-sqlite` | `bun:sqlite`, `Database` from Bun | query sinks, parameterized statement recognition |
| `data/bun-sql` | `Bun.sql`, `Bun.SQL` | SQL template/raw sinks |
| `data/mongoose` | `mongoose` dependency/imports | unvalidated body to DB/document writes |

## Validation adapters

| Adapter ID | Detection evidence | Contributions |
|---|---|---|
| `validation/zod` | `zod` dependency/imports, `.parse`, `.safeParse` | schema parse sanitisers |
| `validation/valibot` | `valibot` dependency/imports, `parse`, `safeParse` | schema parse sanitisers |
| `validation/yup` | `yup` dependency/imports, `.validate` | schema validation sanitisers |
| `validation/joi` | `joi` dependency/imports, `.validate` | schema validation sanitisers |
| `validation/ajv` | `ajv` dependency/imports, compiled validators | JSON schema sanitisers |
| `validation/arktype` | `arktype` dependency/imports | type parser sanitisers |
| `validation/typebox` | `@sinclair/typebox`, TypeBox compiler | JSON schema sanitisers |

## Auth adapters

| Adapter ID | Detection evidence | Contributions |
|---|---|---|
| `auth/better-auth` | `better-auth` dependency/imports, `auth.api.*` | session guard recognition |
| `auth/auth-js` | `next-auth`, `@auth/*`, `getServerSession`, `auth()` | session guard recognition |
| `auth/clerk` | `@clerk/*`, `auth`, `currentUser` | session/user guard recognition |
| `auth/supabase` | `@supabase/*`, `getUser`, `getSession` | session guard recognition |
| `auth/lucia` | `lucia` imports | session guard recognition |
| `auth/custom` | local wrappers like `withAuth`, middleware names | uncertain guard zones, LLM escalation candidates |

## LLM adapters

| Adapter ID | Detection evidence | Contributions |
|---|---|---|
| `llm/openai` | `openai` dependency/imports, `openai.chat.completions.create`, `openai.responses.create` | prompt-injection sinks |
| `llm/anthropic` | `@anthropic-ai/sdk`, `client.messages.create` | prompt-injection sinks |
| `llm/vercel-ai-sdk` | `ai` package, `generateText`, `streamText` | prompt-injection sinks |
| `llm/langchain` | `langchain`, `@langchain/*` | prompt-injection sinks and tool-call boundaries |

## Deployment adapters

Deployment adapters should be advisory at first. They help Stryx
understand runtime boundaries, not style.

| Adapter ID | Detection evidence | Contributions |
|---|---|---|
| `deploy/vercel` | `vercel.json`, Next.js, Vercel env vars | serverless/edge runtime hints |
| `deploy/cloudflare` | `wrangler.toml`, Workers packages | binding/env source and D1/KV/R2 sinks |
| `deploy/aws-lambda` | `serverless.yml`, SST/CDK, Lambda handler names | event body/query/path sources |
| `deploy/netlify` | `netlify.toml`, functions directory | function event sources |
| `deploy/docker` | `Dockerfile`, compose files | no direct taint facts; useful for report context |

## v0.4.0 broad adapter pass

The first stack-aware release ships adapters for every P0 and P1
stack in this catalog simultaneously. A user installing Stryx on a
NestJS + Prisma project gets the same depth of real findings as a
user on Bun + Hono + Drizzle. No first-class stack, no second-class
stack.

Scoping rules per adapter:

- Recognize the 3-5 most common idioms per role
  (source / sink / sanitiser / guard).
- Document remaining gaps in the corresponding rule doc.
- Ship one fixture per (rule × adapter) intersection that
  meaningfully exists (e.g. `flow/sql-injection` × `data/mysql2`,
  `flow/auth-bypass-via-wrapper` × `auth/clerk`).

P2 adapters (deno, cloudflare-workers, elysia, oak, kysely, knex,
bun-sqlite, bun-sql, arktype, typebox, supabase-auth, lucia,
vercel-ai-sdk, langchain) ship as patch releases as real-world
demand surfaces.

## Prioritization

P0:

- `framework/next-backend`
- `framework/hono`
- `framework/express`
- `runtime/node`
- `runtime/bun`
- `data/prisma`
- `data/drizzle`
- `validation/zod`

P1:

- `auth/better-auth`
- `auth/auth-js`
- `llm/openai`
- `llm/anthropic`
- `framework/fastify`
- `framework/nestjs`

P2:

- Deno
- Cloudflare Workers
- Elysia
- Kysely
- Clerk
- Vercel AI SDK

P3:

- deployment-specific advisories
- custom user-defined adapters
- organization policy packs
