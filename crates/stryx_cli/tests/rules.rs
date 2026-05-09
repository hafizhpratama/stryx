//! End-to-end rule tests. Each rule listed in the registry must have
//! a `bad.ts` that fires it and a `good.ts` that does not.
//!
//! These tests drive the same scan path as the CLI binary, so they catch
//! regressions in parsing, traversal, and reporter wiring, not just rule logic.

use std::path::{Path, PathBuf};
use stryx_ast::{parse, Allocator};
use stryx_core::{Finding, Severity};
use stryx_index::ProjectIndex;
use stryx_rules::{builtin_rules, RuleContext};

fn fixtures_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/stryx_cli; fixtures live in
    // <workspace>/tests/fixtures.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .canonicalize()
        .expect("fixtures dir exists")
}

fn scan_file(path: &Path) -> Vec<Finding> {
    let source = std::fs::read_to_string(path).expect("read fixture");
    let allocator = Allocator::default();
    let parsed = parse(&allocator, path, &source).expect("parse fixture");
    let registry = builtin_rules();
    let ctx = RuleContext { file: &parsed, index: None };
    registry
        .rules()
        .iter()
        .flat_map(|r| r.run(&ctx))
        .collect()
}

/// Run the engine's two-pass pipeline over a fixture directory and collect
/// all findings. Mirrors what `stryx scan <dir>` does in the CLI.
fn scan_dir(dir: &Path) -> Vec<Finding> {
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read fixture dir") {
        let entry = entry.expect("dir entry");
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("ts")
            || p.extension().and_then(|e| e.to_str()) == Some("tsx")
        {
            files.push(p);
        }
    }

    let registry = builtin_rules();

    let mut sources: std::collections::HashMap<PathBuf, String> = Default::default();
    for path in &files {
        let source = std::fs::read_to_string(path).expect("read");
        sources.insert(path.clone(), source);
    }

    // Pass 1 — iterative extract (mirrors the CLI's fixed-point loop).
    let mut index = ProjectIndex::new();
    let mut prev_signal = 0usize;
    for round in 0..10 {
        let mut next = ProjectIndex::new();
        for path in &files {
            let allocator = Allocator::default();
            let source = sources.get(path).unwrap();
            let parsed = parse(&allocator, path, source).expect("parse");
            let ctx = RuleContext {
                file: &parsed,
                index: Some(&index),
            };
            for rule in registry.rules() {
                if let Some(summary) = rule.extract(&ctx) {
                    next.insert_file(summary);
                }
            }
        }
        next.finalize();
        let signal: usize = next
            .files()
            .flat_map(|f| f.exports.values())
            .flat_map(|e| e.params.iter())
            .filter(|p| p.reaches_db_sink_unsanitized)
            .count();
        index = next;
        if round > 0 && signal == prev_signal {
            break;
        }
        prev_signal = signal;
    }

    // Pass 2 — run.
    let mut findings = Vec::new();
    for path in &files {
        let allocator = Allocator::default();
        let source = sources.get(path).unwrap();
        let parsed = parse(&allocator, path, source).expect("parse");
        let ctx = RuleContext {
            file: &parsed,
            index: Some(&index),
        };
        for rule in registry.rules() {
            findings.extend(rule.run(&ctx));
        }
    }
    findings
}

#[test]
fn hardcoded_secret_bad_fixture_fires() {
    let path = fixtures_root().join("generic-hardcoded-secret/bad.ts");
    let findings = scan_file(&path);
    assert!(
        !findings.is_empty(),
        "expected findings on bad.ts, got none"
    );
    for f in &findings {
        assert_eq!(f.rule_id, "generic/hardcoded-secret");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.span.file, path);
    }
    assert_eq!(
        findings.len(),
        5,
        "bad.ts has 5 secrets, got {}",
        findings.len()
    );
}

#[test]
fn hardcoded_secret_good_fixture_silent() {
    let path = fixtures_root().join("generic-hardcoded-secret/good.ts");
    let findings = scan_file(&path);
    assert!(
        findings.is_empty(),
        "expected zero findings on good.ts, got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}

#[test]
fn unvalidated_body_to_db_bad_fixture_fires() {
    let path = fixtures_root().join("flow-unvalidated-body-to-db/bad.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db")
        .collect();
    assert_eq!(
        findings.len(),
        4,
        "bad.ts has 4 vulnerable handlers (POST/PUT/PATCH + Hono), got {}: {:?}",
        findings.len(),
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
    for f in &findings {
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.span.file, path);
    }
}

#[test]
fn unvalidated_body_to_db_cross_file_bad_fires() {
    let dir = fixtures_root().join("flow-unvalidated-body-to-db/bad");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db")
        .collect();
    assert!(
        !findings.is_empty(),
        "expected at least one cross-file finding in bad/, got none"
    );
    let route_path = dir.join("route.ts");
    let cross_file_finding = findings
        .iter()
        .find(|f| f.span.file == route_path && f.message.contains("createUser"));
    assert!(
        cross_file_finding.is_some(),
        "expected a cross-file finding on route.ts referencing createUser; got: {:?}",
        findings.iter().map(|f| (&f.span.file, &f.message)).collect::<Vec<_>>(),
    );
}

#[test]
fn unvalidated_body_to_db_three_level_chain_bad_fires() {
    // route → service → repo → prisma. Slice 2 v1's iterative summary
    // computation must converge through three levels of indirection.
    let dir = fixtures_root().join("flow-unvalidated-body-to-db/chain-bad");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db")
        .collect();
    let route_path = dir.join("route.ts");
    assert!(
        findings.iter().any(|f| f.span.file == route_path && f.message.contains("signupUser")),
        "expected a finding on route.ts referencing signupUser; got: {:?}",
        findings.iter().map(|f| (&f.span.file, &f.message)).collect::<Vec<_>>(),
    );
}

#[test]
fn unvalidated_body_to_db_three_level_chain_good_silent() {
    let dir = fixtures_root().join("flow-unvalidated-body-to-db/chain-good");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db")
        .collect();
    assert!(
        findings.is_empty(),
        "expected zero findings on chain-good/, got: {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}

#[test]
fn unvalidated_body_to_db_cross_file_good_silent() {
    let dir = fixtures_root().join("flow-unvalidated-body-to-db/good");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db")
        .collect();
    assert!(
        findings.is_empty(),
        "expected zero flow findings on good/, got: {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}

#[test]
fn unvalidated_body_to_db_good_fixture_silent() {
    let path = fixtures_root().join("flow-unvalidated-body-to-db/good.ts");
    let flow_findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db")
        .collect();
    assert!(
        flow_findings.is_empty(),
        "good.ts uses zod/safeParse — expected zero flow findings, got {:?}",
        flow_findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}
