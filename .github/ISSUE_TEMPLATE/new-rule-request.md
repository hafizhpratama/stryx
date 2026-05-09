---
name: New rule request
about: You found AI generating dangerous TypeScript code Stryx doesn't catch yet
title: "[rule] "
labels: rule-request
assignees: ''
---

> This is the highest-leverage contribution you can make to Stryx. The
> more real-world failure patterns we collect, the more valuable the
> tool gets for everyone.

## Pattern summary

<!-- One sentence: what's the failure mode? -->

## Real-world AI output

**This must be REAL output from an AI tool, not invented.** Synthetic
examples don't represent real failure modes accurately.

> ⚠️ **Licensing**: only paste code you generated yourself by prompting
> an AI tool, or code from a permissively-licensed source you can
> attribute. Do **not** paste proprietary code, copyleft (GPL/LGPL/AGPL)
> code, or other people's code without permission. By submitting, you
> agree to license your contribution under Apache 2.0.

Tool that generated it: <!-- e.g. Cursor, Claude Code, Copilot, v0, Lovable -->
Model (if known): <!-- e.g. Claude Sonnet 4.6, GPT-5, etc. -->
Date: <!-- approximately when was it generated? -->
Original prompt (or close paraphrase):
<!-- "I asked it to..." -->

```ts
// paste the bad code here
```

## Why this is a problem

<!-- What can go wrong? Security flaw? Data loss? Performance issue? -->

## What the correct version looks like

```ts
// paste the fixed version
```

## Framework

- [ ] Next.js (App Router)
- [ ] Next.js (Pages Router)
- [ ] Hono
- [ ] Express
- [ ] Fastify
- [ ] NestJS
- [ ] Generic TypeScript (not framework-specific)
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
