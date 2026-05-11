# Getting Started with Stryx

This guide gets you from zero to your first scan in 5 minutes.

## Install

At v0.1.0 there are two install paths that work today, and three
distribution channels that follow as soon as the npm namespace and
Homebrew tap repo are set up.

### From source — works today

```bash
git clone https://github.com/hafizhpratama/stryx
cd stryx
cargo install --path crates/stryx_cli
```

Needs the Rust toolchain (1.93+). The `stryx` binary lands in
`~/.cargo/bin/`.

### Pre-built binaries — works today

The [v0.1.0 GitHub Release](https://github.com/hafizhpratama/stryx/releases/tag/v0.1.0)
ships archives across five targets (Linux x64/arm64, macOS x64/arm64,
Windows x64):

```bash
# Linux x86_64 example — substitute target for your platform.
curl -L https://github.com/hafizhpratama/stryx/releases/latest/download/stryx-0.1.0-x86_64-unknown-linux-gnu.tar.gz \
  | tar xz
./stryx-0.1.0-x86_64-unknown-linux-gnu/stryx scan
```

Targets available:
- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc` (zip archive)

### Coming soon

- **npm** (`npm install -g stryx` / `npx stryx scan`) — once the
  npm namespace is settled. Pre-built `.node` binaries already
  ship with each GitHub Release.
- **Homebrew** (`brew install stryx/tap/stryx`) — once the Homebrew
  tap repo is set up.
- **Cargo** (`cargo install stryx-cli`) — once published to
  crates.io.

## Your first scan

```bash
cd your-typescript-project
stryx scan
```

Stryx walks your repo respecting `.gitignore`, parses every `.ts` / `.tsx`
file, and reports findings.

Sample output:

```
Stryx 0.1.0 — scanning ./

✗ flow: app/api/users/route.ts → lib/users.ts:4:3
  [high] flow/unvalidated-body-to-db
  Untrusted body reaches db.user.create unsanitized; flow crosses 2 files.
  Cursor/Claude Code commonly scaffold helpers that skip validation.
  → Validate the body with zod/valibot/yup at the entry handler before
    passing it to lib/users.ts:createUser
  Read more: https://stryx.dev/rules/flow-unvalidated-body-to-db

✗ lib/auth.ts:14:1
  [critical] flow/secret-to-response
  Found what appears to be a hardcoded API key reaching a response body.
  → Move this to .env and reference via process.env

Scanned 47 files in 0.3s. Found 2 issues (1 critical, 1 high).
```

The CLI exits with a non-zero status when findings are at or above the
configured severity threshold (default: `high`, configurable via
`--fail-on <severity>`). This makes Stryx naturally suitable for CI
gating.

## Configuration

Stryx reads `stryx.toml` from your project root if present:

```toml
# stryx.toml

[scan]
include = ["app/**", "lib/**", "src/**"]
exclude = ["**/*.test.ts", "**/*.spec.ts", "node_modules/**"]

[severity]
fail_on = "medium"   # info | low | medium | high | critical

[rules]
disabled = ["generic/console-log-in-prod"]

[rules."flow/unvalidated-body-to-db"]
severity = "critical"   # override default

[llm]
enabled = true                    # Layer 3 escalation
provider = "anthropic"            # anthropic | openai | ollama
model = "claude-haiku-4-5"        # cheap, fast, accurate enough
deterministic_only = false        # set true for reproducible CI

[output]
format = "human"   # human | json | sarif | github
```

All settings can also be set via CLI flags. CLI flags win over the file:

```bash
stryx scan --fail-on=high --no-llm --format=json
```

## Common workflows

### Run before push

Add to your `package.json`:

```json
{
  "scripts": {
    "prepush": "stryx scan"
  }
}
```

Combined with [husky](https://typicode.github.io/husky/) or any
git-hook tool, this catches issues before they leave your machine.

### GitHub Actions CI

`.github/workflows/stryx.yml`:

```yaml
name: Stryx
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: stryx/stryx-action@v1
        with:
          fail-on: high
```

Findings appear as inline PR comments via GitHub's annotation API.

### Vercel pre-deploy hook

In `vercel.json`:

```json
{
  "buildCommand": "stryx scan --fail-on=high && next build"
}
```

If Stryx finds high-severity issues, Vercel won't deploy.

### Pre-commit hook

```bash
npx stryx install-hook
```

Installs a `pre-commit` hook that scans only the staged files.

## Reading findings

Each finding has:

- **Severity** — info, low, medium, high, critical
- **Rule ID** — like `flow/unvalidated-body-to-db`, stable forever
- **Span** — file path, line, column
- **Message** — what's wrong, in plain English
- **Fix hint** — suggested remediation
- **Confidence** — present only for LLM-derived findings (0.0 to 1.0)
- **Doc link** — full explanation on stryx.dev

JSON output for scripting:

```bash
stryx scan --format=json | jq '.findings[] | select(.severity=="critical")'
```

## Suppressing false positives

Three ways, in order of preference:

### 1. Inline comment (per-finding)

```ts
// stryx-disable-next-line flow/unvalidated-body-to-db -- public health check, intentional
export async function POST(req: Request) {
  return Response.json({ ok: true });
}
```

The reason after `--` is required. We track suppressions across scans
so you can audit them later.

### 2. File-level

At the top of a file:

```ts
// stryx-disable flow/unvalidated-body-to-db
```

### 3. Project-level

In `stryx.toml`:

```toml
[rules]
disabled = ["flow/unvalidated-body-to-db"]
```

If you find yourself disabling a rule project-wide, please [open an
issue](https://github.com/hafizhpratama/stryx/issues/new) — that's a sign the
rule has too many false positives, and we want to fix it.

## What gets scanned

By default:

- `*.ts`, `*.tsx`, `*.mts`, `*.cts` files
- Respects `.gitignore` and `.stryxignore`
- Skips `node_modules`, `dist`, `build`, `.next`, `coverage`

Override via `stryx.toml` or `--include` / `--exclude` flags.

## What doesn't get scanned (yet)

- `.js` / `.jsx` files — JS-only support is planned for Q4 2026
- `.svelte`, `.vue`, `.astro` — framework-specific files require a
  separate parser; on the roadmap
- Markdown / config files — out of scope

## Updating Stryx

```bash
npm update -g stryx
# or
brew upgrade stryx
# or
cargo install stryx-cli --force
```

We follow SemVer strictly. `npm update` won't pick up MAJOR versions;
review the [CHANGELOG](../CHANGELOG.md) before upgrading those.

## Next steps

- [FAQ](faq.md) — common questions and edge cases
- [Rule library](rules/) — what each rule catches
- [Architecture](../ARCHITECTURE.md) — how Stryx works inside
- [Contributing](../CONTRIBUTING.md) — add a rule, fix a bug

If something is unclear, [open a discussion](https://github.com/hafizhpratama/stryx/discussions).
We use confused-user feedback to fix this guide.
