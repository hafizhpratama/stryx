//! Bench for `flow/redirect-open`.
//!
//! Per AGENTS.md the per-rule per-file p99 budget is ≤ 1ms.
//! Structurally mirrors `flow/ssrf-via-fetch` (same source, different
//! sink set), so the performance profile should match.

use std::hint::black_box;
use std::path::PathBuf;

use criterion::{Criterion, criterion_group, criterion_main};
use stryx_ast::{Allocator, parse};
use stryx_rules::{RuleContext, builtin_rules};

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .canonicalize()
        .expect("fixtures dir exists")
}

fn run_rules(source: &str, path: &std::path::Path) -> usize {
    let allocator = Allocator::default();
    let parsed = parse(&allocator, path, source).expect("parse");
    let registry = builtin_rules();
    let ctx = RuleContext {
        file: &parsed,
        index: None,
    };
    registry.rules().iter().map(|r| r.run(&ctx).len()).sum()
}

fn bench_bad(c: &mut Criterion) {
    let path = fixtures_root().join("flow-redirect-open/bad.ts");
    let source = std::fs::read_to_string(&path).expect("read bad.ts");
    c.bench_function("redirect_open/bad.ts", |b| {
        b.iter(|| run_rules(black_box(&source), black_box(&path)))
    });
}

fn bench_good(c: &mut Criterion) {
    let path = fixtures_root().join("flow-redirect-open/good.ts");
    let source = std::fs::read_to_string(&path).expect("read good.ts");
    c.bench_function("redirect_open/good.ts", |b| {
        b.iter(|| run_rules(black_box(&source), black_box(&path)))
    });
}

criterion_group!(benches, bench_bad, bench_good);
criterion_main!(benches);
