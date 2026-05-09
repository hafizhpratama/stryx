# Frequently Asked Questions

## What is Stryx?

A pre-deploy static analyzer for AI-generated TypeScript. It catches
the specific failure patterns AI coding tools commonly produce —
missing input validation, leaked secrets, weak auth, missing rate
limits — using cross-file taint analysis with optional LLM
confirmation on genuinely ambiguous flows.

## Where does Stryx fit alongside other tools?

Static analysis and AI-code review are crowded spaces, and most
existing tools serve real needs. Here's how Stryx is positioned:

### Generic SAST (Snyk, Semgrep, SonarQube)

These are language-agnostic, broad in coverage, and built for
security teams. Stryx is narrower — TypeScript only — and focuses on
patterns common in AI-generated code, particularly cross-file flows.
Many teams will use Stryx alongside an existing SAST.

A note on Semgrep specifically: their rule library is under the
Semgrep Rules License, which restricts commercial use in competing
products. Stryx writes its detection logic from scratch, using OWASP,
CWE, and analysis of real AI output as references.

### LLM-driven PR review (CodeRabbit, Greptile, Cursor BugBot)

These read PR diffs, prompt a model, and post comments. They reason
about intent across the diff. Stryx is built for the **pre-deploy CLI
workflow**: deterministic AST and index-driven analysis in
milliseconds, with LLM escalation only on the small subset of zones
that are genuinely ambiguous (cached after the first call). The two
shapes are complementary.

### Fast linters (oxlint, Biome)

Excellent for style and correctness in single files. They use the
same parser family Stryx is built on (oxc). Stryx adds a project
semantic index and an inter-procedural taint engine to track flows
across file boundaries, which single-file linters aren't designed
for. Many teams will run both.

### Other AI-aware OSS tools (e.g., VibeSafe)

There are a few open-source projects exploring AI-aware DevSecOps,
each with a different scope. Stryx narrows to TypeScript and goes
deep on cross-file taint flows in that ecosystem. Different tools,
overlapping audiences.

## How do I know if Stryx is the right fit?

Stryx is a good fit if:

- You ship TypeScript with AI assistance.
- You want a pre-deploy gate, not just IDE warnings.
- The patterns you most worry about are flows that span multiple
  files (a route handler that hands off to a helper, an env-var
  config used in a response, a wrapper function that doesn't do what
  its name suggests).
- You want fast, deterministic analysis with optional LLM context on
  ambiguous cases.

Look elsewhere if:

- You need multi-language coverage today (Stryx is TypeScript-only).
- You need a comprehensive enterprise SAST with a long compliance
  feature list — Stryx is narrower than that on purpose.

Many teams will use Stryx alongside ESLint, oxlint, and other tools.
We don't try to replace your toolchain.

## Do you train AI on my code?

**No — Stryx itself does not train any model on your code.** What
happens to code sent to a Layer 3 LLM depends on which client you
configure:

**Bring your own API key.** Stryx is not in the loop. Your provider's
terms govern what happens to the zone content. Review your provider's
data agreement (e.g., Anthropic's zero-data-retention option) before
enabling Layer 3 on sensitive code.

**Local model via `OllamaClient`.** Nothing leaves your network. All
processing is local. Suitable for air-gapped environments.

**Disabled.** Run with `--no-llm` for fully deterministic local
scans. AST and taint analysis are 100% local; only Layer 3 makes any
network calls in the first place.

## Can I use Stryx offline?

Yes. The engine's AST and taint analysis are 100% local — no network
calls. LLM escalation is optional and disabled with `--no-llm`. For
air-gapped environments, point the LLM client at a local Ollama
instance running a code-capable model.

## What languages and frameworks?

**Language:** TypeScript (`.ts`, `.tsx`, `.mts`, `.cts`). JavaScript
support is on the roadmap.

**Frameworks with framework-aware rules:**
- Next.js — App Router and Pages Router (v0.1).
- Hono and Express — added via source/sink adapters in a later phase.
- Generic TypeScript — covered.

We prioritize framework support based on what AI tools generate most.

## How accurate is Stryx?

**Layer 2 (AST + index + taint).** High precision by design; lower
recall as a tradeoff. False positives erode trust faster than false
negatives, so each rule is tuned conservatively. Every rule has a
documented set of false-positive zones and tests asserting both
matching and non-matching fixtures.

**Layer 3 (LLM escalation).** Used only on zones the static analysis
flagged as uncertain. Returns a confidence score; verdicts below a
threshold are dropped or surfaced as info-level only.

If you encounter a false positive, please report it — it's some of
the highest-leverage feedback for the project.

## I found a false positive — what do I do?

1. Suppress locally with an inline comment that includes a reason
   (e.g., `// stryx-disable-next-line <rule-id> -- signed webhook`).
2. [Open an issue](https://github.com/hafizhpratama/stryx/issues/new) with a
   minimal repro.

We'll either tighten the rule or update the docs to clarify when it
should fire.

## I want a rule that doesn't exist — how do I get it?

[Open a rule request](https://github.com/hafizhpratama/stryx/issues/new?template=new-rule-request.md)
with a real example of the failure mode. The more concrete the
example (real AI output, the prompt that produced it, why it's
dangerous), the easier the rule is to write well.

## Can I write my own rules?

Yes. The current path is to fork the repo, add a Rust rule following
the [rule template](rules/_template.md), and submit a PR (or run
locally if it's project-specific). A plugin model that doesn't
require forking is on the roadmap; the design is being weighed
between WASM and a Rust crate-plugin pattern.

## How do I support the project?

- ⭐ Star the repo — helps with discoverability.
- Open issues for false positives, rule requests, and bugs.
- Submit PRs — see [CONTRIBUTING.md](../CONTRIBUTING.md).
- [GitHub Sponsors](https://github.com/sponsors/stryx) if you'd like
  to fund development directly.

## Is Stryx affiliated with Anthropic, Cursor, GitHub, or any AI tool vendor?

No. Stryx is an independent open-source project. The default Layer 3
client targets Anthropic's API because their model and terms suit
the use case well, but the `LlmClient` trait is provider-pluggable —
OpenAI, local Ollama, and other providers are first-class. Stryx is
vendor-neutral on which AI tool generated the code being scanned.

## I have another question

[Open a GitHub discussion](https://github.com/hafizhpratama/stryx/discussions)
or email hello@stryx.dev.
