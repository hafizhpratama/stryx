//! End-to-end rule tests. Each rule listed in the registry must have
//! a `bad.ts` that fires it and a `good.ts` that does not.
//!
//! These tests drive the same scan path as the CLI binary, so they catch
//! regressions in parsing, traversal, and reporter wiring, not just rule logic.

use std::path::{Path, PathBuf};
use stryx_ast::{Allocator, parse};
use stryx_core::{Finding, Severity};
use stryx_index::ProjectIndex;
use stryx_rules::{RuleContext, builtin_rules};

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
    let ctx = RuleContext {
        file: &parsed,
        index: None,
    };
    registry.rules().iter().flat_map(|r| r.run(&ctx)).collect()
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

/// Variant of `scan_dir` that returns the converged index instead of
/// the findings, so tests can inspect summary-level state (param
/// flows, offsets) without re-running the engine.
fn extract_index(dir: &Path) -> ProjectIndex {
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
        sources.insert(path.clone(), std::fs::read_to_string(path).expect("read"));
    }
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
    index
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
        7,
        "bad.ts has 7 vulnerable handlers (POST/PUT/PATCH + Hono + drizzle insert/update + NestJS), got {}: {:?}",
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
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
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
        findings
            .iter()
            .any(|f| f.span.file == route_path && f.message.contains("signupUser")),
        "expected a finding on route.ts referencing signupUser; got: {:?}",
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
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

/// Slice 2 of ADR 0006 — the per-param simulation should now record
/// first-field offsets for member-chain reads on the tainted param.
/// The boolean signal continues to be authoritative for findings; this
/// test only inspects the new field.
#[test]
fn unvalidated_body_to_db_records_param_side_offsets() {
    use stryx_taint::Offset;

    let dir = fixtures_root().join("flow-unvalidated-body-to-db/offset-recording");
    let index = extract_index(&dir);
    let lib = index
        .files()
        .find(|f| {
            f.exports.contains_key("upsertNamed")
                && f.exports.contains_key("createWhole")
                && f.exports.contains_key("updateLiteralKey")
                && f.exports.contains_key("updateAnyKey")
        })
        .expect("offset-recording/lib.ts summary present in index");

    let upsert = lib.exports.get("upsertNamed").expect("upsertNamed export");
    let upsert_param = upsert.params.first().expect("one param");
    assert!(upsert_param.reaches_db_sink_unsanitized);
    assert_eq!(
        upsert_param.tainted_offsets,
        vec![Offset::Field("email".into()), Offset::Field("name".into())],
        "upsertNamed: expected sorted Field(email), Field(name) — got {:?}",
        upsert_param.tainted_offsets
    );

    let whole = lib.exports.get("createWhole").expect("createWhole export");
    let whole_param = whole.params.first().expect("one param");
    assert!(whole_param.reaches_db_sink_unsanitized);
    assert!(
        whole_param.tainted_offsets.is_empty(),
        "createWhole: bare-ident pass-through should record no offsets — got {:?}",
        whole_param.tainted_offsets
    );

    let lit = lib
        .exports
        .get("updateLiteralKey")
        .expect("updateLiteralKey export");
    let lit_param = lit.params.first().expect("one param");
    assert_eq!(
        lit_param.tainted_offsets,
        vec![Offset::Field("password".into())],
        "updateLiteralKey: computed[lit] should record Field(\"password\") — got {:?}",
        lit_param.tainted_offsets
    );

    let any = lib
        .exports
        .get("updateAnyKey")
        .expect("updateAnyKey export");
    let any_param = any.params.first().expect("one param");
    assert_eq!(
        any_param.tainted_offsets,
        vec![Offset::Any],
        "updateAnyKey: computed[non-literal] should collapse to Any — got {:?}",
        any_param.tainted_offsets
    );
}

/// Slice 3c of ADR 0006 — cross-file site records caller-side offsets
/// AND absorbs the callee's offsets when the caller passes a bare
/// tainted ident (no chain to capture locally).
#[test]
fn unvalidated_body_to_db_propagates_offsets_cross_file() {
    use stryx_taint::Offset;

    let dir = fixtures_root().join("flow-unvalidated-body-to-db/offset-recording-crossfile");
    let index = extract_index(&dir);
    let lib = index
        .files()
        .find(|f| {
            f.exports.contains_key("writeName")
                && f.exports.contains_key("callerWithChain")
                && f.exports.contains_key("callerBare")
        })
        .expect("offset-recording-crossfile/lib.ts summary present");

    // The leaf callee reads its param's `.name` field locally — the
    // first-field walker on the local sink picks this up.
    let writer = lib.exports.get("writeName").expect("writeName export");
    let writer_param = writer.params.first().expect("one param");
    assert_eq!(
        writer_param.tainted_offsets,
        vec![Offset::Field("name".into())],
        "writeName: local sink should record Field(\"name\") — got {:?}",
        writer_param.tainted_offsets,
    );

    // Caller passes `body.user`. The caller's own walk on the chain
    // records `Field("user")`. Composing the callee's `Field("name")`
    // through the chain is a follow-on slice; here we just assert the
    // chain-side offset lands.
    let chain_caller = lib
        .exports
        .get("callerWithChain")
        .expect("callerWithChain export");
    let chain_param = chain_caller.params.first().expect("one param");
    assert!(
        chain_param
            .tainted_offsets
            .contains(&Offset::Field("user".into())),
        "callerWithChain: expected `user` in {:?}",
        chain_param.tainted_offsets,
    );

    // Caller passes bare `body`. The caller's own walk records
    // nothing (no chain). The callee's `Field("name")` should be
    // absorbed via the bare-ident composition path.
    let bare_caller = lib.exports.get("callerBare").expect("callerBare export");
    let bare_param = bare_caller.params.first().expect("one param");
    assert_eq!(
        bare_param.tainted_offsets,
        vec![Offset::Field("name".into())],
        "callerBare: expected callee's Field(\"name\") absorbed — got {:?}",
        bare_param.tainted_offsets,
    );
}

#[test]
fn unvalidated_body_to_db_barrel_re_export() {
    // route imports from "./lib" which is a barrel index that
    // re-exports from "./lib/users". Stryx must chase the
    // re-export chain to find the prisma write.
    let dir = fixtures_root().join("flow-unvalidated-body-to-db/barrel-bad");
    let result = stryx_cli::scan(&dir).expect("scan");
    let route_path = dir.join("route.ts");
    let cross_file_finding = result.findings.iter().find(|f| {
        f.rule_id == "flow/unvalidated-body-to-db"
            && f.span.file == route_path
            && f.message.contains("createUser")
    });
    assert!(
        cross_file_finding.is_some(),
        "expected cross-file finding through barrel re-export; got: {:?}",
        result
            .findings
            .iter()
            .map(|f| (&f.rule_id, &f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn unvalidated_body_to_db_tsconfig_paths_resolved() {
    // Real-world Next.js shape: route imports through `@/*` path
    // alias to `./src/*`. Without tsconfig.json reading, the
    // resolver rejects non-relative specifiers and the cross-file
    // flow is missed entirely. We use stryx_cli::scan so the full
    // CLI path runs (including tsconfig parsing).
    let dir = fixtures_root().join("flow-unvalidated-body-to-db/tsconfig-paths-bad");
    let result = stryx_cli::scan(&dir).expect("scan");
    let route_path = dir.join("app/api/route.ts");
    let cross_file_finding = result.findings.iter().find(|f| {
        f.rule_id == "flow/unvalidated-body-to-db"
            && f.span.file == route_path
            && f.message.contains("createUser")
    });
    assert!(
        cross_file_finding.is_some(),
        "expected cross-file finding through `@/lib/users` alias; got: {:?}",
        result
            .findings
            .iter()
            .map(|f| (&f.rule_id, &f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn unvalidated_body_to_db_validate_wrapper_silent() {
    // `export default validate(handler)` where `validate`'s body
    // calls `Schema.parse(req.body)` before delegating. The inner
    // handler's `req.body` reads should NOT taint — the wrapper has
    // already enforced the schema. Real-world FP from cal.com
    // vital/save.ts.
    let path = fixtures_root().join("flow-unvalidated-body-to-db/validate-wrapper/good.ts");
    let source = std::fs::read_to_string(&path).expect("read fixture");
    let allocator = Allocator::default();
    let parsed = parse(&allocator, &path, &source).expect("parse fixture");
    let registry = builtin_rules();

    // Run extract once to populate the index, then run.
    let mut index = ProjectIndex::new();
    let summaries: Vec<_> = {
        let extract_index = ProjectIndex::new();
        let ctx = RuleContext {
            file: &parsed,
            index: Some(&extract_index),
        };
        registry
            .rules()
            .iter()
            .filter_map(|r| r.extract(&ctx))
            .collect()
    };
    for s in summaries {
        index.insert_file(s);
    }
    index.finalize();
    let ctx = RuleContext {
        file: &parsed,
        index: Some(&index),
    };
    let findings: Vec<_> = registry
        .rules()
        .iter()
        .flat_map(|r| r.run(&ctx))
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db")
        .collect();
    assert!(
        findings.is_empty(),
        "wrapper validates req.body via Schema.parse — expected zero findings, got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}

#[test]
fn unvalidated_body_to_db_where_only_emits_medium() {
    // Body field used purely as a primary-key filter in a Prisma where
    // clause; the data block is hardcoded. Rule fires at Medium, not
    // High — `--fail-on=high` CI gates won't break, but the issue is
    // surfaced for review.
    let path = fixtures_root().join("flow-unvalidated-body-to-db/where-only/bad.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db")
        .collect();
    assert_eq!(findings.len(), 1, "expected exactly one where-only finding");
    let f = &findings[0];
    assert_eq!(
        f.severity,
        Severity::Medium,
        "where-only path must downgrade to Medium, got {:?}; message: {}",
        f.severity,
        f.message,
    );
    assert!(
        f.message.contains("`where`"),
        "message should call out the where-clause shape; got: {}",
        f.message,
    );
}

#[test]
fn auth_bypass_via_wrapper_bad_fires() {
    // route.ts wraps an admin handler in withAuth, but lib.ts's
    // withAuth is a no-op `return handler`. Stryx should follow the
    // import and flag the export at the call site.
    let dir = fixtures_root().join("flow-auth-bypass-via-wrapper/bad");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/auth-bypass-via-wrapper")
        .collect();
    let route_path = dir.join("route.ts");
    assert!(
        findings
            .iter()
            .any(|f| f.span.file == route_path && f.message.contains("withAuth")),
        "expected an auth-bypass finding on route.ts referencing withAuth; got: {:?}",
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
    for f in &findings {
        assert_eq!(f.severity, Severity::Critical);
    }
}

#[test]
fn auth_bypass_via_wrapper_good_silent() {
    // Same shape, but lib.ts calls getServerSession and short-circuits.
    let dir = fixtures_root().join("flow-auth-bypass-via-wrapper/good");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/auth-bypass-via-wrapper")
        .collect();
    assert!(
        findings.is_empty(),
        "good/'s wrapper calls getServerSession — expected zero findings, got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}

#[test]
fn secret_to_response_bad_fires() {
    let path = fixtures_root().join("flow-secret-to-response/bad.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/secret-to-response")
        .collect();
    assert_eq!(
        findings.len(),
        6,
        "bad.ts has 6 secret leaks (App Router dump, indirect, Pages res.json, hardcoded credential, Hono, new Response), got {}: {:?}",
        findings.len(),
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
    for f in &findings {
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.span.file, path);
    }
}

#[test]
fn secret_to_response_good_silent() {
    let path = fixtures_root().join("flow-secret-to-response/good.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/secret-to-response")
        .collect();
    assert!(
        findings.is_empty(),
        "good.ts uses Boolean()/redact()/destructure-and-drop — expected zero findings, got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}

#[test]
fn unvalidated_body_to_db_nest_bad_fires() {
    // NestJS shape: controller method receives @Body() and delegates to
    // an injected service via `this.userService.create(body)`. The
    // service's `create` method writes to prisma without validation.
    // Cross-class taint must follow the field-injection chain.
    let dir = fixtures_root().join("flow-unvalidated-body-to-db/nest-bad");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db")
        .collect();
    let controller_path = dir.join("controller.ts");
    assert!(
        findings.iter().any(
            |f| f.span.file == controller_path && f.message.contains("this.userService.create")
        ),
        "expected a cross-class finding on controller.ts referencing this.userService.create; got: {:?}",
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn unvalidated_body_to_db_nest_good_silent() {
    // Same shape as nest-bad, but the controller parses the body with
    // `createUserSchema.parse(body)` before delegating to the service.
    let dir = fixtures_root().join("flow-unvalidated-body-to-db/nest-good");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db")
        .collect();
    assert!(
        findings.is_empty(),
        "expected zero findings on nest-good/, got: {:?}",
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
