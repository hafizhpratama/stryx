# Third-Party Licenses

Stryx is built on the work of many open-source projects. This
document tracks every direct dependency and its license.

To regenerate this file once the engine is buildable:

```bash
cargo about generate about.hbs > THIRD_PARTY_LICENSES.md
```

Last regenerated: 2026-05-09 (manual placeholder until automation lands).

## Direct dependencies

| Crate | License | Purpose |
|---|---|---|
| `oxc_parser` | MIT | TypeScript / JavaScript parser |
| `oxc_ast` | MIT | AST node types |
| `oxc_semantic` | MIT | Scope and symbol resolution |
| `oxc_resolver` | MIT | Module resolution |
| `oxc_allocator` | MIT | Arena allocator (bumpalo wrapper) |
| `rayon` | MIT OR Apache-2.0 | Data parallelism |
| `dashmap` | MIT | Concurrent hashmap |
| `clap` | MIT OR Apache-2.0 | CLI argument parsing |
| `serde` | MIT OR Apache-2.0 | Serialization framework |
| `serde_json` | MIT OR Apache-2.0 | JSON support for serde |
| `tokio` | MIT | Async runtime (LLM HTTP boundary only) |
| `reqwest` | MIT OR Apache-2.0 | HTTP client (LLM calls) |
| `rustls` | MIT OR Apache-2.0 OR ISC | TLS implementation |
| `tracing` | MIT | Structured logging |
| `tracing-subscriber` | MIT | Tracing output formatting |
| `criterion` | MIT OR Apache-2.0 | Benchmarking framework |
| `thiserror` | MIT OR Apache-2.0 | Error type derive macros |
| `anyhow` | MIT OR Apache-2.0 | Generic error handling |
| `ignore` | Unlicense OR MIT | gitignore-aware file traversal |
| `blake3` | CC0 OR Apache-2.0 | Cache key hashing |
| `rusqlite` | MIT | On-disk cache (SQLite-backed) |
| `napi-rs` | MIT | Rust ↔ Node.js bindings (npm distribution) |

## Indirect dependencies

The full transitive dependency tree is licensed under permissive
licenses (MIT, Apache-2.0, BSD, ISC, Unlicense, or dual-licensed
combinations).

Stryx will not knowingly include any GPL, LGPL, AGPL, SSPL, BSL, or
other copyleft / source-available code in its dependency tree. CI
runs `cargo deny check licenses` on every commit to enforce this.

## Inspirations (not code dependencies)

We've learned from these projects without copying their code:

- **ESLint plugin ecosystem** — common JS/TS patterns and rule shapes.
- **Semgrep's public rule documentation** — pattern catalogs (we did
  not copy their rules; the Semgrep Rules License restricts use in
  competing products, so our rules are written from scratch).
- **OWASP Top 10** — vulnerability category framing.
- **CWE catalog** — industry-standard pattern descriptions.

## Reporting license issues

If you believe Stryx violates the license of any dependency, please
email **legal@stryx.dev** with the details. We take license
compliance seriously and will investigate promptly.

## Licensing of Stryx itself

Stryx is licensed under [Apache 2.0](LICENSE).
