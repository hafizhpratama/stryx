//! Bench for `flow/xss-via-dangerously-set-inner-html`.
//!
//! Per AGENTS.md the per-rule per-file p99 budget is ≤ 1ms.
//! The hot path here is the JSX-attribute walk inside React component
//! returns — slice 1 only fires when a `dangerouslySetInnerHTML` attr
//! is present, so most files cost only the per-attribute name check.

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
    let path = fixtures_root().join("flow-xss-via-dangerously-set-inner-html/bad.tsx");
    let source = std::fs::read_to_string(&path).expect("read bad.tsx");
    c.bench_function("xss_via_dangerously_set_inner_html/bad.tsx", |b| {
        b.iter(|| run_rules(black_box(&source), black_box(&path)))
    });
}

fn bench_good(c: &mut Criterion) {
    let path = fixtures_root().join("flow-xss-via-dangerously-set-inner-html/good.tsx");
    let source = std::fs::read_to_string(&path).expect("read good.tsx");
    c.bench_function("xss_via_dangerously_set_inner_html/good.tsx", |b| {
        b.iter(|| run_rules(black_box(&source), black_box(&path)))
    });
}

criterion_group!(benches, bench_bad, bench_good);
criterion_main!(benches);
