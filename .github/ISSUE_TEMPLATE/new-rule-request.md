---
name: New rule request
about: You found a dangerous JavaScript/TypeScript backend flow Stryx doesn't catch yet
title: "[rule] "
labels: rule-request
assignees: ''
---

> This is the highest-leverage contribution you can make to Stryx. The
> more real-world failure patterns we collect, the more valuable the
> tool gets for everyone.

## Pattern summary

<!-- One sentence: what's the failure mode? -->

## Minimal reproduction

Prefer the smallest JavaScript/TypeScript example that preserves the real
source, sink, guard, framework, and cross-file shape.

> ⚠️ **Licensing**: only paste code you wrote yourself or code from a
> permissively-licensed source you can attribute. Do **not** paste
> proprietary code, copyleft (GPL/LGPL/AGPL) code, or other people's code
> without permission. By submitting, you agree to license your
> contribution under Apache 2.0.

Stack: <!-- e.g. Bun + Hono + Drizzle + Zod -->
Where this came from: <!-- production bug, local repro, OSS example, tutorial pattern -->

```ts
// paste the bad code or minimal reproduction here
```

## Why this is a problem

<!-- What can go wrong? Security flaw? Data loss? Performance issue? -->

## What the correct version looks like

```ts
// paste the fixed version
```

## What should Stryx recognize as fixed?

<!-- Be concrete: zod.safeParse + success check, host allow-list before fetch,
     parameterized query, session guard before handler, etc. -->

## Runtime / framework

- [ ] Bun
- [ ] Node.js
- [ ] Deno
- [ ] Next.js (App Router)
- [ ] Next.js (Pages Router)
- [ ] Hono
- [ ] Express
- [ ] Fastify
- [ ] NestJS
- [ ] Generic TypeScript (not framework-specific)
- [ ] Other: 

## Stack surface

- [ ] Runtime
- [ ] Framework/router
- [ ] Database/query layer
- [ ] Validation
- [ ] Auth/session
- [ ] LLM SDK
- [ ] Filesystem/process/network
- [ ] Other:

## Suggested severity

- [ ] info — notable but not a problem
- [ ] low — minor concern, no immediate risk
- [ ] medium — real issue, not directly exploitable
- [ ] high — likely bug or security issue
- [ ] critical — severe, exploitable, actively dangerous

## Suggested rule ID

<!-- Format: <category>/<kebab-case-name>, e.g. flow/unvalidated-body-to-db,
     sources/nextjs-request-body, sinks/db-write, sanitizers/zod-parse -->

## How often have you seen this?

<!-- 1 time / a few times / common pattern / extremely common -->

## False positive zones we should be careful about

<!-- Are there cases that LOOK like this but are actually fine? -->

## Are you willing to help implement?

- [ ] Yes, I can implement it
- [ ] Yes, with guidance
- [ ] No, just reporting

## Additional context

<!-- Links to OWASP / CWE entries, related real-world incidents, etc. -->
