# `generic/hardcoded-secret`

> Catches credential-shaped string literals committed directly in source.

## Metadata

| Field | Value |
|---|---|
| Rule ID | `generic/hardcoded-secret` |
| Status | experimental |
| Severity | critical / high depending on provider pattern |
| Frameworks | generic TypeScript / JavaScript |
| Default | enabled |
| Added in | v0.1.0 |

## What this rule catches

Hardcoded secrets are credentials embedded directly in source code:
provider API keys, cloud access keys, payment keys, and personal access
tokens. Once committed, they are easy to leak through Git history,
package publication, client bundles, logs, screenshots, or AI context.

Stryx flags string literals that match well-known credential prefixes for
AWS, Anthropic, Stripe, GitHub, and OpenAI-shaped keys. The rule is
conservative by design; generic high-entropy detection is noisy and
belongs behind an opt-in mode.

## Why this happens

Hardcoded secrets often start as local test configuration or
provider-shaped examples in SDK setup code. Someone replaces the
placeholder with a real key, commits the file, and the value then lives
in source history even after the current line is removed.

## Bad example

```ts
// Repro: provider-shaped secrets are committed in source.

export const config = {
  anthropicKey: "sk-ant-api03-FIXTUREFAKEFIXTUREFAKEFIXTUR",
  stripeKey: "sk_test_FIXTUREFAKEKEYFIXTURE",
};
```

## Good example

```ts
export const config = {
  anthropicKey: process.env.ANTHROPIC_API_KEY,
  stripeKey: process.env.STRIPE_SECRET_KEY,
};
```

The source code contains only environment-variable reads. The actual
credential is supplied by the runtime environment or secret manager.

## How to fix

Move credentials out of source and into the deployment platform's secret
store or environment variables. Rotate any secret that was already
committed, because removing it from the current file does not remove it
from Git history or package caches.

If the key is only a fixture, make that explicit with a non-provider
shape that cannot be mistaken for a real credential.

## What Stryx recognizes

Recognized as safe:

- `process.env.SECRET_NAME` reads.
- Values loaded from a secret manager client.
- Non-provider-shaped placeholders such as `"test-api-key"` in tests.

Not recognized as safe:

- Provider-shaped string literals in source, even if they are intended as
  examples.
- Secrets stored in exported config objects.
- Secrets embedded in request headers.
- Comments saying a key is fake while the literal matches a real provider
  pattern.

## Taint signature

Not applicable — this is a direct string-literal rule, not a source to
sink flow rule.

## Detection logic

1. Walk every string literal in each JavaScript/TypeScript file.
2. Skip short strings below the minimum credential length.
3. Match the literal value against conservative provider-specific regexes.
4. Emit a finding at the literal span with provider-specific severity and
   help text.

The rule currently recognizes:

- AWS access key IDs (`AKIA...`)
- Anthropic API keys (`sk-ant-...`)
- Stripe secret keys (`sk_live_...`, `sk_test_...`)
- GitHub personal access tokens (`ghp_...`)
- OpenAI-shaped keys (`sk-...`)

## Known false positive zones

- **Fixture keys** that intentionally use provider-shaped examples
  → Prefer non-provider-shaped placeholders. Suppress only when the exact
  provider shape is required by a test.
- **Documentation examples** committed in source files
  → Use clearly fake values that do not match live provider prefixes.

## LLM escalation prompt (Layer 3)

Not applicable — this rule is fully deterministic at the AST layer.

## Performance characteristics

- AST analysis: negligible; one regex pass per string literal longer than
  the minimum credential length.
- No cross-file index required.
- No LLM escalation.

## Configuration

```toml
[rules."generic/hardcoded-secret"]
severity = "critical"
```

Future-slice options:

```toml
[rules."generic/hardcoded-secret"]
allow_test_fixtures = true
extra_patterns = ["my-provider-prefix-[A-Za-z0-9]{32}"]
```

## Suppressing this rule

Inline:

```ts
// stryx-disable-next-line generic/hardcoded-secret -- fixture requires provider-shaped example
```

File-level:

```ts
// stryx-disable generic/hardcoded-secret
```

Project-level (`stryx.toml`):

```toml
[rules]
disabled = ["generic/hardcoded-secret"]
```

## See also

- OWASP A02:2021 — Cryptographic Failures
- CWE-798 — Use of Hard-coded Credentials
- GitHub secret scanning documentation
- AWS guidance on rotating access keys

## History

| Version | Change |
|---|---|
| v0.1.0 | Initial provider-prefix detection for AWS, Anthropic, Stripe, GitHub, and OpenAI-shaped keys. |
