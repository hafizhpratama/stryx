# Pull Request

## What does this PR do?

<!-- One or two sentences. Link the issue if applicable. -->

Closes #

## Type of change

<!-- Check all that apply -->

- [ ] New rule (`feat(rules): ...`)
- [ ] Rule fix or improvement (`fix(rules): ...`)
- [ ] Engine / parser / pipeline change (`feat/fix(core): ...` etc.)
- [ ] Documentation only (`docs: ...`)
- [ ] Performance improvement (`perf: ...`)
- [ ] Refactor (no behavior change) (`refactor: ...`)
- [ ] Build / CI / tooling (`chore: ...`)

## Checklist

### Always

- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] `cargo fmt --all` is clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean
- [ ] `cargo test --workspace` passes locally
- [ ] CHANGELOG.md updated under `[Unreleased]`
- [ ] All new code is your own work or permissively-licensed
      (MIT / Apache 2.0 / BSD / similar). No copyleft (GPL/LGPL/AGPL),
      no source-available licenses (BSL/SSPL), no Semgrep rules.
      By submitting, you license your contribution under Apache 2.0.

### If adding a new rule

- [ ] Bad fixture with a comment explaining the source → sink shape and
      stack surface. Single file for single-file rules; a `bad/`
      directory for cross-file flow rules.
- [ ] Bad fixture is your own minimal reproduction or permissively-
      licensed code you can attribute (no closed-source pulls, no GPL).
- [ ] Good fixture (file or `good/` directory) showing the safe version.
- [ ] Rule documentation in `docs/rules/<category>-<rule-id>.md`
      (e.g. `flow-unvalidated-body-to-db.md`) following the template,
      including the **How to fix**, **What Stryx recognizes**, and
      **Taint signature** sections.
- [ ] `taint_signature()` and `scope()` declared on the `Rule` impl
      per [ADR 0003](../docs/decisions/0003-cross-file-and-taint-as-core.md).
- [ ] Integration test in `tests/rules.rs`
- [ ] Criterion benchmark in `benches/rules.rs`
- [ ] Rule registered in `crates/stryx_rules/src/registry.rs`
      (or the relevant source/sink/sanitizer registry in `stryx_taint`)
- [ ] If LLM escalation: prompt template in
      `crates/stryx_llm/prompts/<category>/<rule-id>.txt`
- [ ] Updated `docs/rules/README.md` index
- [ ] CLI message/fix hint points to the same remediation described in
      the rule doc

### If modifying engine / pipeline

- [ ] Existing tests still pass
- [ ] No new `Box<dyn Trait>` in hot paths (use enum dispatch)
- [ ] No new `oxc_*` imports leaked into `stryx_rules` (the contract
      test catches this; verify locally with
      `! grep -rE "use oxc_" crates/stryx_rules/src/`)
- [ ] No async added to AST traversal layers
- [ ] Performance budget respected (criterion shows no >10% regression)

### If touching public API

- [ ] Breaking changes are flagged in CHANGELOG with migration notes
- [ ] If pre-1.0: documented in commit message and CHANGELOG
- [ ] If post-1.0: PR title prefixed with `BREAKING:` and accompanying
      deprecation period if removing rather than adding

## Performance impact

<!-- For PRs that touch hot paths, paste before/after criterion numbers -->

```
[ before / after / delta ]
```

## How to test this manually

<!-- Commands the reviewer can run to see this working -->

```bash
cargo run --bin stryx -- scan ./tests/fixtures/<rule-id>/bad.ts
```

## Notes for reviewer

<!-- Anything non-obvious. Design decisions you considered. Tradeoffs. -->

## Screenshots / output

<!-- If the change affects CLI output, paste before and after -->
