//! Microbench for `generic/hardcoded-secret`.
//!
//! Establishes the perf baseline so regressions show up immediately. Per
//! CLAUDE.md hard rule #7 the per-rule per-file budget is ≤ 1ms p99.

use std::hint::black_box;
use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, Criterion};
use stryx_ast::{parse, Allocator};
use stryx_rules::{builtin_rules, RuleContext};

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
    let ctx = RuleContext { file: &parsed, index: None };
    registry.rules().iter().map(|r| r.run(&ctx).len()).sum()
}

fn bench_bad_fixture(c: &mut Criterion) {
    let path = fixtures_root().join("generic-hardcoded-secret/bad.ts");
    let source = std::fs::read_to_string(&path).expect("read bad.ts");
    c.bench_function("hardcoded_secret/bad.ts", |b| {
        b.iter(|| run_rules(black_box(&source), black_box(&path)))
    });
}

fn bench_good_fixture(c: &mut Criterion) {
    let path = fixtures_root().join("generic-hardcoded-secret/good.ts");
    let source = std::fs::read_to_string(&path).expect("read good.ts");
    c.bench_function("hardcoded_secret/good.ts", |b| {
        b.iter(|| run_rules(black_box(&source), black_box(&path)))
    });
}

criterion_group!(benches, bench_bad_fixture, bench_good_fixture);
criterion_main!(benches);
