//! Bench for `flow/auth-bypass-via-wrapper`.
//!
//! Per CLAUDE.md hard rule #7 the per-rule per-file p99 budget is ≤ 1ms.
//! This rule is a single forward walk that consults the project index;
//! the bench measures the full scan_dir path through the engine's
//! two-pass pipeline so the cross-file resolution cost is included.

use std::hint::black_box;
use std::path::{Path, PathBuf};

use criterion::{Criterion, criterion_group, criterion_main};
use stryx_ast::{Allocator, parse};
use stryx_index::ProjectIndex;
use stryx_rules::{RuleContext, builtin_rules};

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .canonicalize()
        .expect("fixtures dir exists")
}

fn scan_dir(dir: &Path) -> usize {
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read fixture dir") {
        let entry = entry.expect("dir entry");
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("ts") {
            files.push(p);
        }
    }

    let registry = builtin_rules();
    let mut sources: std::collections::HashMap<PathBuf, String> = Default::default();
    for path in &files {
        sources.insert(path.clone(), std::fs::read_to_string(path).expect("read"));
    }

    // Pass 1 — extract.
    let mut index = ProjectIndex::new();
    for _ in 0..2 {
        let mut next = ProjectIndex::new();
        for path in &files {
            let allocator = Allocator::default();
            let parsed = parse(&allocator, path, sources.get(path).unwrap()).expect("parse");
            let ctx = RuleContext {
                file: &parsed,
                index: Some(&index),
            };
            for rule in registry.rules() {
                if let Some(s) = rule.extract(&ctx) {
                    next.insert_file(s);
                }
            }
        }
        next.finalize();
        index = next;
    }

    // Pass 2 — run.
    let mut count = 0;
    for path in &files {
        let allocator = Allocator::default();
        let parsed = parse(&allocator, path, sources.get(path).unwrap()).expect("parse");
        let ctx = RuleContext {
            file: &parsed,
            index: Some(&index),
        };
        for rule in registry.rules() {
            count += rule.run(&ctx).len();
        }
    }
    count
}

fn bench_bad(c: &mut Criterion) {
    let dir = fixtures_root().join("flow-auth-bypass-via-wrapper/bad");
    c.bench_function("auth_bypass_via_wrapper/bad", |b| {
        b.iter(|| scan_dir(black_box(&dir)))
    });
}

fn bench_good(c: &mut Criterion) {
    let dir = fixtures_root().join("flow-auth-bypass-via-wrapper/good");
    c.bench_function("auth_bypass_via_wrapper/good", |b| {
        b.iter(|| scan_dir(black_box(&dir)))
    });
}

criterion_group!(benches, bench_bad, bench_good);
criterion_main!(benches);
