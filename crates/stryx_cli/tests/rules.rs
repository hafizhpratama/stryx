//! End-to-end rule tests. Each rule listed in the registry must have
//! a `bad.ts` that fires it and a `good.ts` that does not.
//!
//! These tests drive the same scan path as the CLI binary, so they catch
//! regressions in parsing, traversal, and reporter wiring, not just rule logic.

use std::path::{Path, PathBuf};
use stryx_ast::{parse, Allocator};
use stryx_core::{Finding, Severity};
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
    let ctx = RuleContext { file: &parsed };
    registry
        .rules()
        .iter()
        .flat_map(|r| r.run(&ctx))
        .collect()
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
