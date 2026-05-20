//! Bench for `flow/ssrf-via-fetch`.
//!
//! Per AGENTS.md the per-rule per-file p99 budget is ≤ 1ms.
//! Slice 1 is single-file with no call-summary lookups, so this rule
//! sits well within the per-rule budget.

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
        adapters: None,
    };
    registry.rules().iter().map(|r| r.run(&ctx).len()).sum()
}

fn bench_bad(c: &mut Criterion) {
    let path = fixtures_root().join("flow-ssrf-via-fetch/bad.ts");
    let source = std::fs::read_to_string(&path).expect("read bad.ts");
    c.bench_function("ssrf_via_fetch/bad.ts", |b| {
        b.iter(|| run_rules(black_box(&source), black_box(&path)))
    });
}

fn bench_good(c: &mut Criterion) {
    let path = fixtures_root().join("flow-ssrf-via-fetch/good.ts");
    let source = std::fs::read_to_string(&path).expect("read good.ts");
    c.bench_function("ssrf_via_fetch/good.ts", |b| {
        b.iter(|| run_rules(black_box(&source), black_box(&path)))
    });
}

criterion_group!(benches, bench_bad, bench_good);
criterion_main!(benches);
