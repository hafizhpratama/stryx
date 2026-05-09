# Changelog

All notable changes to Stryx are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and Stryx adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Categories

- **Added** — new features
- **Changed** — changes to existing functionality
- **Deprecated** — features still working but being phased out
- **Removed** — features removed in this release
- **Fixed** — bug fixes
- **Security** — vulnerabilities fixed

---

## [Unreleased]

### Added
- Initial project scaffolding
- Core architecture documentation, including ADRs 0001–0004
- AI agent context files (CLAUDE.md, AGENTS.md, .github/copilot-instructions.md)
- Contributor guidelines

### Coming soon (v0.1, planned)
- Foundational crates `stryx_index` (project semantic index) and
  `stryx_taint` (inter-procedural taint engine), per ADR 0003
- Three v0.1 flow rules: `flow/unvalidated-body-to-db`,
  `flow/auth-bypass-via-wrapper`, `flow/secret-to-response`
- CLI binary distributed via `cargo install` and Homebrew
- GitHub Action for pre-deploy / pre-merge gating

### Coming later (Phase 2+)
- napi-rs npm distribution
- Additional flow rules and single-file table-stakes rules
- Hono and Express framework support via source/sink adapters
- Plugin model for community rules (WASM and/or crate-plugin pattern)
- Type-aware analysis via deeper `oxc_semantic` integration

---

## Release process

When we tag a release:

1. Move all `[Unreleased]` items into a new dated section
2. Tag the commit: `git tag -a v0.1.0 -m "Release 0.1.0"`
3. GitHub Actions builds and publishes to crates.io and npm
4. Release notes are auto-generated from this changelog

## SemVer guarantees

- **MAJOR** version bumps when we change CLI flags, JSON output schema,
  rule IDs, or public Rust APIs
- **MINOR** version bumps when we add rules, add output formats, add
  framework support — backwards-compatible additions only
- **PATCH** version bumps for bug fixes and dependency updates

We try to deprecate features for at least one MINOR cycle before removing
them in a MAJOR release.

## Versioning notes for rules

Rules have their own version implicit in the Stryx version that ships them.
A rule's behavior may improve across versions (catches more correctly,
fewer false positives), but its `rule_id` is stable forever. If we ever
need to change a rule's semantics meaningfully, we'd ship it as a new ID
and deprecate the old one.

[Unreleased]: https://github.com/hafizhpratama/stryx/compare/v0.0.0...HEAD
