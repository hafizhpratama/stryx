# Contributing to Stryx

Thank you for considering contributing. Stryx grows by
community-contributed JavaScript and TypeScript backend security patterns:
unsafe flows, missing guards, weak validation, dangerous sinks, and stack
adapters that help the analyzer understand real projects.

## Ways to contribute

In rough order of leverage:

1. **Report a rule request** — you found a dangerous backend flow we don't
   yet catch. [Open a rule request](.github/ISSUE_TEMPLATE/new-rule-request.md)
   with a minimal reproduction. This is the highest-impact contribution.
2. **Implement a requested rule** — there's a "good first issue" label for
   rules with clear specs but no implementation.
3. **Fix a false positive** — open a PR with a `tests/fixtures/` example
   that should NOT trigger but does, and the fix.
4. **Improve a rule's message or fix guide** — small, valuable, easy reviews.
5. **Performance improvements** — backed by `cargo bench` numbers.
6. **Documentation** — typo fixes, clearer examples, missing FAQ entries.

## Quick dev setup

Requirements:
- Rust 1.93+ (use `rustup`) — `rust-toolchain.toml` pins the exact channel.
- Node.js 20+ (only for `stryx_napi` once npm distribution lands).

```bash
git clone https://github.com/hafizhpratama/stryx.git
cd stryx
cargo build --workspace
cargo test --workspace
```

If everything passes, you're ready to go.

## Adding a new rule

This is the most common contribution. We follow a strict workflow because
rule quality matters more than rule quantity.

### 1. Find the failure in the wild

Start from a real backend security failure pattern. Prefer a minimal
reproduction that preserves the actual source, sink, guard, and
cross-file shape. Save the bad code in:

```
tests/fixtures/<rule-id>/bad.ts
```

For example: `tests/fixtures/flow/unvalidated-body-to-db/bad/`
(directory for cross-file flows; single file for non-flow rules).

Add a comment at the top explaining the source of the pattern:

```ts
// Repro: request body reaches a DB write across route.ts -> lib/users.ts
// Source: reported from a production-style Hono + Drizzle app
```

### License compliance for fixtures (important)

Fixtures must be **your own code** or material you have explicit
permission to redistribute under Apache 2.0:

- Minimal reproduction written by you — fine.
- Public examples from official tutorials when the tutorial is
  permissively licensed and you cite the source — fine, but check the
  license.
- Pulled from another open-source repo without checking — **not fine**.
  Even MIT-licensed code requires attribution; copyleft code (GPL,
  LGPL, AGPL) cannot be redistributed under our Apache 2.0 license.
- Pulled from a closed-source codebase you have access to — never.

We also do not copy detection rules from other projects (especially
Semgrep, whose rules library has a license that restricts use in
competing products). If you study patterns from elsewhere, write the
detection from scratch in our format, informed by the technique not
the code.

When in doubt, write a small reproduction yourself and document the
source/sink/guard shape in the comment header.

### 2. Write the doc first

Create `docs/rules/<category>-<rule-id>.md` (e.g.
`flow-unvalidated-body-to-db.md`) following the
[rule template](docs/rules/_template.md). This forces clarity *before*
you start writing detection logic. Includes:

- Severity and frameworks
- What the rule catches (one paragraph)
- Why this happens (the failure mode)
- Bad and good code examples
- How to fix the unsafe flow
- What Stryx recognizes as fixed
- Detection logic in plain English
- Known false positive zones
- The LLM escalation prompt (Layer 3 fallback)

Rule docs are fix guides, not generic best-practice essays. Be explicit
about the safe pattern and the analyzer's current accepted shapes.

### 3. Implement the rule

Pick the right folder under `crates/stryx_rules/src/`:

- `flows/` for cross-cutting taint rules (the most common contribution)
- `sources/` for new untrusted-data sources
- `sinks/` for new dangerous-operation detectors
- `sanitizers/` for new validators / escapers / auth wrappers

Then implement the `Rule` trait. See
[docs/architecture/rule-format.md](docs/architecture/rule-format.md)
for the trait signature, including `interests()`, `taint_signature()`,
and `scope()` per [ADR 0003](docs/decisions/0003-cross-file-and-taint-as-core.md).

Reference implementation: `crates/stryx_rules/src/flows/unvalidated_body_to_db.rs`.

### 4. Add a `good.ts` fixture

`tests/fixtures/<rule-id>/good.ts` shows the correct version. The same
pattern but with the safety mechanism in place. Tests assert zero findings
on this file.

### 5. Write the integration test

In `tests/rules.rs`, add:

```rust
#[test]
fn flow_unvalidated_body_to_db() {
    assert_findings("flow/unvalidated-body-to-db/bad/", &["flow/unvalidated-body-to-db"]);
    assert_no_findings("flow/unvalidated-body-to-db/good/");
}
```

Cross-file flow rules use directory fixtures rather than single files
because the flow spans multiple sources.

### 6. Add a criterion benchmark

In `benches/rules.rs`, add a bench for the new rule. We track regressions.
A rule that takes 50ms/file is suspicious — most should be < 1ms/file.

### 7. Register the rule

Add the rule to `crates/stryx_rules/src/registry.rs` so it's loaded at
runtime.

### 8. Update CHANGELOG.md

Add an entry under `[Unreleased]`:

```
### Added
- Rule `flow/unvalidated-body-to-db` catches API handlers (Next.js, Hono,
  Express) that pass request body to a DB write without zod/valibot/yup
  along the path, even when the flow crosses files. (#123)
```

### 9. Open the PR

Use the [PR template](.github/PULL_REQUEST_TEMPLATE.md). The checklist
ensures all the above steps are done.

## Code style

- `cargo fmt --all` before every commit (CI enforces)
- `cargo clippy --workspace --all-targets -- -D warnings` (CI enforces)
- Prefer `&str` over `String` in hot paths
- Prefer `match` over chained `if let`
- Use `thiserror` for library errors, `anyhow` only at binary boundaries
- Use `tracing::instrument` on public functions
- No `unwrap()` in non-test code; use `?` and proper error types

## Testing requirements

Every PR should include tests appropriate to the change:

- **New rule**: unit test (in the rule file) + integration test (in
  `tests/rules.rs`) + fixture files + criterion bench
- **Bug fix**: a test that fails before the fix and passes after
- **Performance change**: a criterion bench showing the improvement
- **Refactor**: existing tests should still pass; if they don't, the
  refactor is breaking something

Run `cargo test --workspace` and `cargo bench --workspace` before pushing.

## Commit messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(rules): add flow/unvalidated-body-to-db
fix(parser): handle TSX with embedded JSX correctly
docs: fix typo in getting-started.md
perf(ast): use enum dispatch in visitor (-12% scan time)
chore(deps): bump oxc_parser to 0.40
```

Types we use: `feat`, `fix`, `docs`, `perf`, `refactor`, `test`, `chore`.

This format powers automatic changelog generation and SemVer decisions.

## PR review process

- A maintainer reviews within 48 hours
- We may ask for changes — please don't take it personally; rule quality
  affects every user
- Once approved, we squash-merge with the conventional commit format
- Your contribution shows up in the next release's CHANGELOG

## Reporting bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug-report.md).
Include:

- Stryx version (`stryx --version`)
- OS and Rust version
- Minimal reproducing TypeScript code
- Expected behavior
- Actual behavior

A good bug report is one we can reproduce in 5 minutes.

## Reporting security issues

**Do not open a public issue for security vulnerabilities.** See
[SECURITY.md](SECURITY.md) for the disclosure process.

## Communication

- **GitHub Discussions**: feature ideas, design discussions, "how do I…"
- **GitHub Issues**: bugs, rule requests, feature requests
- **Email**: maintainers@stryx.dev for anything sensitive
- **Twitter/X**: [@stryxdev](https://twitter.com/stryxdev) for updates

## Code of Conduct

By contributing, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).
We're building a tool for everyone shipping JavaScript and TypeScript
backends. Be kind.

## Licensing

By contributing, you agree your contributions will be licensed under
[Apache 2.0](LICENSE), the same as the rest of the project. You retain
copyright; we retain the right to redistribute under the same terms.

## Recognition

Contributors are listed in [CHANGELOG.md](CHANGELOG.md) for each release
they contribute to. Significant contributors are added to the README's
acknowledgments section.
