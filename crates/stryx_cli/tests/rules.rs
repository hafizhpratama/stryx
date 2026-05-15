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
    let raw: Vec<Finding> = registry.rules().iter().flat_map(|r| r.run(&ctx)).collect();
    // Apply the same post-rule suppression filter the CLI binary
    // does; otherwise `// stryx-disable-next-line` markers in
    // fixtures would never take effect under `scan_file`.
    let mut sources = std::collections::HashMap::new();
    sources.insert(path.to_path_buf(), source);
    stryx_cli::filter_suppressed(raw, &sources)
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
        // Convergence signal: sum of both per-rule sink flags
        // across exports and locals. A mid-flight fetch-sink flip
        // would otherwise get masked by a stable db-sink count.
        // Production uses `ConvergenceSignal` (a full tuple); the
        // test harness uses a single sum because the fixtures we
        // exercise here converge within 2 rounds.
        let signal: usize = next
            .files()
            .flat_map(|f| f.exports.values().chain(f.locals.values()))
            .flat_map(|e| e.params.iter())
            .map(|p| {
                usize::from(p.reaches_db_sink_unsanitized)
                    + usize::from(p.reaches_fetch_sink_unsanitized)
                    + usize::from(p.reaches_redirect_sink_unsanitized)
            })
            .sum();
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
    // Apply the same post-rule suppression filter the CLI does.
    stryx_cli::filter_suppressed(findings, &sources)
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
        // Convergence signal: sum of both per-rule sink flags
        // across exports and locals. A mid-flight fetch-sink flip
        // would otherwise get masked by a stable db-sink count.
        // Production uses `ConvergenceSignal` (a full tuple); the
        // test harness uses a single sum because the fixtures we
        // exercise here converge within 2 rounds.
        let signal: usize = next
            .files()
            .flat_map(|f| f.exports.values().chain(f.locals.values()))
            .flat_map(|e| e.params.iter())
            .map(|p| {
                usize::from(p.reaches_db_sink_unsanitized)
                    + usize::from(p.reaches_fetch_sink_unsanitized)
                    + usize::from(p.reaches_redirect_sink_unsanitized)
            })
            .sum();
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

/// Slice 3.5 of ADR 0007 — smoke-test the cross-file return-shape
/// wiring at variable bindings. The fixture has a real chain
/// (`const result = passthrough(body); const final = passthrough
/// (result); ...`); slice 3.5's `compute_call_return_shape` runs
/// at each `const`, looking up the helper's `return_shape` and
/// instantiating it with the caller's local shape. Behaviour-
/// level: the existing prisma sink still fires once per export.
/// Substrate-level: each `const` stores a precise shape that
/// future consumer slices will read.
#[test]
fn unvalidated_body_to_db_return_shape_chain_substrate_smoke() {
    let dir = fixtures_root().join("flow-unvalidated-body-to-db/return-shape-cross-file");
    let result = stryx_cli::scan(&dir).expect("scan");
    let lib_path = dir.join("lib.ts");
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db" && f.span.file == lib_path)
        .collect();
    // POST and PUT each fire one prisma.user.create finding through
    // the chain; the boolean propagation path catches both regardless
    // of slice 3.5. The substrate-level shape precision isn't
    // asserted here (no exposed visitor inspection); future slices
    // that read `local_shape` at sink sites will get tests for that.
    assert_eq!(
        findings.len(),
        2,
        "expected POST and PUT chain findings to both fire; got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
    for f in &findings {
        assert!(
            f.message.contains("prisma.user.create"),
            "expected prisma.user.create in message, got: {}",
            f.message,
        );
    }
}

/// Local-shape-at-sink consumer (ADR 0007 follow-up to slice 3.5).
/// When a chain like `const id = pickId(body); sink({ where: { id } })`
/// reaches the DB sink, the bare-ident `id` carries the rich shape
/// stored by slice 3.5 (`Obj{id: Tainted+Bot}` for `pickId`). The
/// sink-side recorder reads that shape and merges it into the
/// route's param_shape — without this wiring, the chain collapses
/// to whole-value `Tainted+Bot` at the sink even though the
/// upstream return-shape was already known.
#[test]
fn unvalidated_body_to_db_local_shape_propagates_at_sink() {
    use stryx_taint::{Offset, Shape};

    let dir = fixtures_root().join("flow-unvalidated-body-to-db/local-shape-sink");
    let index = extract_index(&dir);
    let route = index
        .files()
        .find(|f| f.exports.contains_key("POST"))
        .expect("route.ts summary present");
    let post = route.exports.get("POST").expect("POST export");
    let req_param = post.params.first().expect("POST has one param");
    let shape = req_param
        .param_shape
        .as_ref()
        .expect("POST.req records a shape (chain reaches DB sink)");
    match &shape.shape {
        Shape::Obj(map) => {
            assert!(
                map.contains_key(&Offset::Field("id".into())),
                "expected Field(\"id\") at top level — slice 3.5 stored \
                 Obj{{id: Tainted+Bot}} for the local `id`, the bare-ident \
                 sink consumer should propagate it into req's param_shape; \
                 got {map:?}",
            );
        }
        other => panic!(
            "expected Obj shape from local-shape propagation, got {other:?} \
             — without the bare-ident consumer the shape collapses to Bot \
             with whole-value xtaint, which is the regression this slice fixes",
        ),
    }
}

/// Task #95 regression — observed on trigger.dev's Remix routes
/// (apps/webapp/app/routes/_app.orgs...alerts/route.tsx and
/// siblings) during 2026-05-11 OSS validation. The
/// `@conform-to/zod` library uses a free-function `parse(input,
/// { schema })` shape, not the member-call `<schema>.parse(input)`
/// form Stryx originally recognised. Stryx now treats the
/// free-function call as a sanitizer when the second argument is
/// an object literal containing a `schema` property. Generic
/// `parse(x, y)` calls (e.g. base-conversion parsers) must NOT
/// match — the third case in the fixture asserts a finding still
/// fires when the conform shape isn't present.
#[test]
fn unvalidated_body_to_db_conform_parse_recognised_as_sanitizer() {
    let dir = fixtures_root().join("flow-unvalidated-body-to-db/conform-parse");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db")
        .collect();

    let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();

    // CASE 1 + CASE 2: conform-parse forms should suppress.
    // The handlers are `conformParse` and `conformParseAliased`; if
    // either fires, the recogniser failed.
    let conform_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.message.contains("prisma.user.update")
                && !messages.iter().any(|m| m.contains("genericParse"))
                && f.span.file.to_string_lossy().ends_with("lib.ts")
        })
        .collect();
    // The findings list should have exactly one — the CASE 3
    // genericParse handler. Both conform-parse cases must be silent.
    assert_eq!(
        findings.len(),
        1,
        "expected exactly one finding (CASE 3 only); conform `parse(x, {{ schema }})` \
         in CASES 1 and 2 must be recognised as sanitizer. got: {messages:?}",
    );
    assert!(
        findings[0].message.contains("prisma.user.update"),
        "the remaining finding should be on the genericParse → prisma.user.update path; \
         got: {}",
        findings[0].message,
    );
    let _ = conform_findings; // silence the dead-let in case future
    // refactoring drops the variable.
}

/// Task #96 regression — observed on trigger.dev's
/// admin.api.v1/v2.orgs.$organizationId.feature-flags.ts routes
/// during 2026-05-11 OSS validation. The pattern:
///
///   const body = await req.json();
///   const result = validatePartialFeatureFlags(body);
///   if (!result.success) return ...;
///   // body flows to prisma.organization.update
///
/// `validatePartialFeatureFlags` is a custom validator returning
/// `{success: true, data: T} | {success: false, error: ...}`. The
/// early-return guard on `!result.success` proves the validator
/// accepted the body. Stryx tracks `validator_inits` lineage at
/// the var declaration, then the IfStatement narrowing path
/// consumes it when the test matches `!X.success` / `!X.ok` and
/// the branch returns.
///
/// The fixture pins 5 cases: 3 suppression boundaries (canonical
/// shape, `.ok` discriminant, `body as T` cast) and 2 firing
/// boundaries (non-validator callee name, missing guard) to keep
/// the heuristic from over-suppressing.
#[test]
fn unvalidated_body_to_db_discriminant_validator_guard() {
    let dir = fixtures_root().join("flow-unvalidated-body-to-db/discriminant-validator");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db")
        .collect();

    let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();

    // CASES 1-3 must suppress: zero findings on validatorGuard,
    // validatorOkGuard, validatorWithCast — each performs
    // body→prisma.user.update past a recognised validator guard.
    //
    // CASES 4 (nonValidatorName) and 5 (missingGuard) must still
    // fire — both use body in prisma.user.update without a
    // recognised validator guard.
    //
    // Total: exactly 2 findings, both on the same prisma sink.
    assert_eq!(
        findings.len(),
        2,
        "expected exactly two findings (CASES 4 + 5); validator-guard \
         suppression in CASES 1-3 must hold. got: {messages:?}",
    );
    for f in &findings {
        assert!(
            f.message.contains("prisma.user.update"),
            "remaining findings should be on prisma.user.update; got: {}",
            f.message,
        );
    }
}

/// Task #92 regression — observed on documenso's `getSession`
/// helper during real-world OSS validation. When a body-tainted
/// parameter flows into a DB-writing helper through a wrapping
/// call expression (e.g. `dbWritingHelper(passthrough(c))`), the
/// cross-file finding emits but `record_taint_in_arg` doesn't
/// recurse into the call wrapper. Pre-fix, the slice 2.5 invariant
/// `reaches == !findings.is_empty()` fired a debug-assert panic
/// because the shape stayed empty.
///
/// The fix is a conservative fallback in `record_taint_in_arg`:
/// when the expression is `expr_is_tainted_readonly` but doesn't
/// match any structural shape we recognise, record whole-value
/// root taint. The shape becomes `Tainted+Bot` — agrees with the
/// finding-emission path.
#[test]
fn unvalidated_body_to_db_call_wrapped_sink_records_root_taint() {
    use stryx_taint::{Shape, Xtaint};

    let dir = fixtures_root().join("flow-unvalidated-body-to-db/call-wrapped-sink");
    let index = extract_index(&dir);
    let lib = index
        .files()
        .find(|f| f.exports.contains_key("getSession"))
        .expect("call-wrapped-sink lib summary present");
    let helper = lib.exports.get("getSession").expect("getSession export");
    let c_param = helper.params.first().expect("getSession has one param");
    let shape = c_param.param_shape.as_ref().expect(
        "getSession.c records a shape — finding fires for the cross-file \
             writing helper, and the slice 2.5 invariant requires the shape \
             to be non-empty when findings are non-empty",
    );
    // Root-level whole-value taint: Xtaint::Tainted + Shape::Bot.
    // The conservative fallback records exactly this when the
    // tainted expression doesn't fit a structural shape.
    assert!(
        matches!(shape.xtaint, Xtaint::Tainted(_)),
        "expected Xtaint::Tainted at root after call-wrapped sink fallback, got {:?}",
        shape.xtaint,
    );
    assert_eq!(
        shape.shape,
        Shape::Bot,
        "expected Shape::Bot — the fallback is a conservative root-level recording, \
         not an attempt to model the wrapper callee's return shape (which would \
         require ADR 0007 slice 3.5's compute_call_return_shape, available only \
         at variable bindings)",
    );
    // And `reaches_db_sink_unsanitized` (derived from the shape per
    // slice 2.5) should agree with the emitted finding.
    assert!(
        c_param.reaches_db_sink_unsanitized,
        "reaches_db_sink_unsanitized derived from param_shape must be true when \
         the cross-file finding fires",
    );
}

/// Symmetric counterpart to the param-side local-shape consumer:
/// when a helper delegates through a chain helper and returns the
/// local, `record_taint_in_return` reads the local's slice-3.5
/// shape and propagates it into the helper's `return_shape`.
/// Without this wiring, delegate's return_shape collapses to
/// whole-value `Tainted+Bot`, dropping field info that future
/// callers could otherwise consume.
#[test]
fn unvalidated_body_to_db_local_shape_propagates_at_return() {
    use stryx_taint::{Offset, Shape};

    let dir = fixtures_root().join("flow-unvalidated-body-to-db/local-shape-return");
    let index = extract_index(&dir);
    let lib = index
        .files()
        .find(|f| f.exports.contains_key("delegate") && f.exports.contains_key("pickId"))
        .expect("local-shape-return lib summary present");
    let delegate = lib.exports.get("delegate").expect("delegate export");
    let param = delegate.params.first().expect("delegate has one param");
    let rs = param
        .return_shape
        .as_ref()
        .expect("delegate records a return_shape (chain reaches return)");
    match &rs.shape {
        Shape::Obj(map) => {
            assert!(
                map.contains_key(&Offset::Field("id".into())),
                "expected Field(\"id\") at top level — slice 3.5 stored \
                 Obj{{id: Tainted+Bot}} on the local `id`, the bare-ident \
                 return consumer should propagate it into delegate's \
                 return_shape; got {map:?}",
            );
        }
        other => panic!(
            "expected Obj shape from local-shape return propagation, got {other:?} \
             — without the bare-ident consumer the chain collapses to whole-value \
             Tainted+Bot at the return site, which is the regression this slice fixes",
        ),
    }
}

/// Slice 3.1 of ADR 0007 — the visitor populates `param.return_shape`
/// from return-statement observations. Mirrors the slice-2.1c
/// `param_shape` test but for the return side. Observation-only —
/// the existing `propagates_to_return` boolean still drives
/// cross-file finding emission.
#[test]
fn unvalidated_body_to_db_populates_return_shape() {
    use stryx_taint::{Offset, Shape, Xtaint};

    let dir = fixtures_root().join("flow-unvalidated-body-to-db/return-shape");
    let index = extract_index(&dir);
    let lib = index
        .files()
        .find(|f| f.exports.contains_key("passthrough") && f.exports.contains_key("pickId"))
        .expect("return-shape lib summary present");

    // passthrough(b): return b — whole-value. return_shape is
    // Tainted+Bot.
    let pt = lib.exports.get("passthrough").expect("passthrough");
    let rs = pt
        .params
        .first()
        .and_then(|p| p.return_shape.as_ref())
        .expect("passthrough has return_shape");
    assert!(matches!(rs.xtaint, Xtaint::Tainted(_)));
    assert_eq!(rs.shape, Shape::Bot);

    // pickId(b): return b.id — chain. return_shape =
    // Obj{id: Tainted+Bot}.
    let pi = lib.exports.get("pickId").expect("pickId");
    let rs = pi
        .params
        .first()
        .and_then(|p| p.return_shape.as_ref())
        .expect("pickId has return_shape");
    assert_eq!(rs.xtaint, Xtaint::None);
    match &rs.shape {
        Shape::Obj(map) => {
            let id_cell = map.get(&Offset::Field("id".into())).expect("id key");
            assert!(matches!(id_cell.xtaint, Xtaint::Tainted(_)));
        }
        other => panic!("expected Obj{{id}}, got {other:?}"),
    }

    // shape(body): return {id: body.id, data: body.data} — slice 3.1
    // limitation means the recorded shape carries both .id and
    // .data on the param side, not the return-object structure.
    let sh = lib.exports.get("shape").expect("shape");
    let rs = sh
        .params
        .first()
        .and_then(|p| p.return_shape.as_ref())
        .expect("shape has return_shape");
    match &rs.shape {
        Shape::Obj(map) => {
            assert!(map.contains_key(&Offset::Field("id".into())));
            assert!(map.contains_key(&Offset::Field("data".into())));
        }
        other => panic!("expected Obj{{id, data}}, got {other:?}"),
    }

    // noop(b): return 42 — nothing tainted flows out. return_shape
    // is None (canonicalize prunes the bare-bot recording).
    let nm = lib.exports.get("noop").expect("noop");
    let nm_param = nm.params.first().expect("one param");
    assert!(
        nm_param.return_shape.is_none(),
        "noop should have no return_shape; got {:?}",
        nm_param.return_shape
    );

    // constant(b): same — return doesn't reference the param.
    let ct = lib.exports.get("constant").expect("constant");
    assert!(ct.params.first().expect("one param").return_shape.is_none());
}

/// Slice 2.3a of ADR 0006 — the producer emits an `Arg(arg_id)`
/// placeholder for parameters with no observed taint reads, instead
/// of leaving `param_shape` as `None`. Concrete observations still
/// produce concrete shapes; Arg only fills the "no info" gap.
#[test]
fn unvalidated_body_to_db_emits_arg_placeholder_for_unobserved_params() {
    use stryx_taint::{Cell, Shape};

    let dir = fixtures_root().join("flow-unvalidated-body-to-db/arg-placeholder");
    let index = extract_index(&dir);
    let lib = index
        .files()
        .find(|f| f.exports.contains_key("noop") && f.exports.contains_key("withOptions"))
        .expect("arg-placeholder/lib.ts summary present");

    // `noop(unused)` makes no sink reads — its shape should be the
    // polymorphic placeholder, not None.
    let noop = lib.exports.get("noop").expect("noop export");
    let unused_param = noop.params.first().expect("one param");
    let shape = unused_param
        .param_shape
        .as_ref()
        .expect("Arg placeholder produced for un-observed param");
    match &shape.shape {
        Shape::Arg(id) => {
            assert_eq!(id.fn_id, "noop");
            assert_eq!(id.idx, 0);
        }
        other => panic!("expected Arg placeholder, got {other:?}"),
    }

    // `withOptions(body, opts)` — body is observed at the sink,
    // opts is not. Param 0 (body) gets a concrete Tainted+Bot shape;
    // param 1 (opts) gets the Arg placeholder.
    let with_opts = lib.exports.get("withOptions").expect("withOptions export");
    assert_eq!(with_opts.params.len(), 2);
    let body_shape = with_opts.params[0]
        .param_shape
        .as_ref()
        .expect("body has observed shape");
    assert!(matches!(body_shape.shape, Shape::Bot));
    let opts_shape = with_opts.params[1]
        .param_shape
        .as_ref()
        .expect("opts gets Arg placeholder");
    match &opts_shape.shape {
        Shape::Arg(id) => {
            assert_eq!(id.fn_id, "withOptions");
            assert_eq!(id.idx, 1);
        }
        other => panic!("expected Arg(withOptions, 1), got {other:?}"),
    }
    // Sanity: the constructor produces what we expect.
    assert_eq!(
        opts_shape,
        &Cell::arg_placeholder(stryx_taint::ArgId {
            fn_id: "withOptions".into(),
            idx: 1,
        })
    );
}

/// Slice 2.2 of ADR 0006 — first consumer of `param_shape`. When a
/// cross-file finding fires and the callee's shape reveals specific
/// top-level Field offsets, the finding message lists them so users
/// see which body fields flow through the helper.
#[test]
fn unvalidated_body_to_db_cross_file_message_lists_callee_fields() {
    // route.ts: POST handler sources `body = req.json()` and calls
    // saveProfile(body). saveProfile reads input.name and input.email
    // at the sink, so its param_shape is `Obj{email, name}` and the
    // cross-file finding in route.ts lists both fields.
    let dir = fixtures_root().join("flow-unvalidated-body-to-db/cross-file-fields");
    let result = stryx_cli::scan(&dir).expect("scan");
    let route_path = dir.join("route.ts");
    let cross_file: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.rule_id == "flow/unvalidated-body-to-db"
                && f.span.file == route_path
                && f.message.contains("`saveProfile`")
        })
        .collect();
    assert!(
        !cross_file.is_empty(),
        "expected cross-file finding through saveProfile in route.ts; got: {:?}",
        result
            .findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
    for f in &cross_file {
        assert!(
            f.message.contains("`email`") && f.message.contains("`name`"),
            "cross-file finding should list both `email` and `name`; got: {}",
            f.message,
        );
        assert!(
            f.message.contains("fields:"),
            "expected `fields:` prefix in: {}",
            f.message,
        );
    }
}

/// Slice 2.1d of ADR 0006 — at the cross-file site the caller's
/// `param_shape` absorbs the callee's `param_shape`, grafted at the
/// caller's offset chain. `callerBare(body)` calling
/// `writeName(input)` (which records `Obj{name: Tainted}`) should
/// produce `body.param_shape = Obj{name: Tainted}`. `callerWithChain
/// (body)` calling `writeName(body.user)` should produce
/// `body.param_shape = Obj{user: Obj{name: Tainted}}`.
#[test]
fn unvalidated_body_to_db_composes_shapes_cross_file() {
    use stryx_taint::{Offset, Shape, Xtaint};

    let dir = fixtures_root().join("flow-unvalidated-body-to-db/offset-recording-crossfile");
    let index = extract_index(&dir);
    let lib = index
        .files()
        .find(|f| f.exports.contains_key("writeName"))
        .expect("offset-recording-crossfile lib summary present");

    // The leaf callee records Obj{name: Tainted} on its param.
    let writer = lib.exports.get("writeName").expect("writeName");
    let writer_shape = writer
        .params
        .first()
        .and_then(|p| p.param_shape.as_ref())
        .expect("writeName has a param_shape");
    match &writer_shape.shape {
        Shape::Obj(map) => {
            assert!(map.contains_key(&Offset::Field("name".into())));
        }
        other => panic!("writeName: expected Obj, got {other:?}"),
    }

    // Bare-ident caller: shape is the callee's, merged at root.
    let bare = lib.exports.get("callerBare").expect("callerBare");
    let bare_shape = bare
        .params
        .first()
        .and_then(|p| p.param_shape.as_ref())
        .expect("callerBare absorbs callee shape");
    match &bare_shape.shape {
        Shape::Obj(map) => {
            let name_cell = map
                .get(&Offset::Field("name".into()))
                .expect("name field grafted at root");
            assert!(matches!(name_cell.xtaint, Xtaint::Tainted(_)));
        }
        other => panic!("callerBare: expected Obj{{name}}, got {other:?}"),
    }

    // Chain caller: shape is callee's, grafted under `.user`.
    let chain = lib.exports.get("callerWithChain").expect("callerWithChain");
    let chain_shape = chain
        .params
        .first()
        .and_then(|p| p.param_shape.as_ref())
        .expect("callerWithChain absorbs callee shape under chain");
    match &chain_shape.shape {
        Shape::Obj(map) => {
            let user = map
                .get(&Offset::Field("user".into()))
                .expect("user field at root from local-side chain record");
            // Under .user the callee's shape lives; .user.name is
            // tainted from the cross-file composition.
            match &user.shape {
                Shape::Obj(inner) => {
                    let name = inner
                        .get(&Offset::Field("name".into()))
                        .expect("user.name leaf grafted from callee");
                    assert!(matches!(name.xtaint, Xtaint::Tainted(_)));
                }
                Shape::Bot => {
                    // The local-side full_chain records `body.user`
                    // as Tainted at .user (bare leaf, no inner Obj).
                    // The cross-file insert_shape_at_path then walks
                    // into .user and merges the callee's Obj{name}
                    // there. `merge_into` says "Obj over Bot
                    // replaces Bot with Obj," but our existing entry
                    // is Tainted/Bot, not None/Bot, so the source's
                    // shape gets installed via the Bot→Obj branch.
                    panic!("expected user to have Obj sub-shape from cross-file composition");
                }
                Shape::Arg(_) => {
                    panic!("Arg placeholder shouldn't appear here — no producer yet");
                }
            }
        }
        other => panic!("callerWithChain: expected Obj{{user}}, got {other:?}"),
    }
}

/// Slice 2.1c of ADR 0006 — the visitor populates a `param_shape`
/// `Cell` tree alongside the flat `tainted_offsets`. The shape is
/// canonicalized, so a function with no member-chain reads gets
/// `None` (whole-value taint canonicalizes to `None+Bot ⇒ drop`),
/// while chain reads produce a nested `Obj`.
#[test]
fn unvalidated_body_to_db_populates_param_shape() {
    use stryx_taint::{Offset, Shape, Xtaint};

    let dir = fixtures_root().join("flow-unvalidated-body-to-db/offset-recording");
    let index = extract_index(&dir);
    let lib = index
        .files()
        .find(|f| f.exports.contains_key("upsertNamed"))
        .expect("offset-recording lib summary present");

    // upsertNamed reads body.name and body.email at the sink. The
    // shape should be `None+Obj{ email: Tainted, name: Tainted }`.
    let upsert = lib.exports.get("upsertNamed").expect("upsertNamed");
    let upsert_param = upsert.params.first().expect("one param");
    let shape = upsert_param
        .param_shape
        .as_ref()
        .expect("upsertNamed records a shape (chain reads observed)");
    assert_eq!(shape.xtaint, Xtaint::None);
    match &shape.shape {
        Shape::Obj(map) => {
            assert!(map.contains_key(&Offset::Field("name".into())));
            assert!(map.contains_key(&Offset::Field("email".into())));
            assert!(matches!(
                map.get(&Offset::Field("name".into())).map(|c| &c.xtaint),
                Some(Xtaint::Tainted(_))
            ));
        }
        other => panic!("expected Obj, got {other:?}"),
    }

    // createWhole spreads the param as-is into the sink — no
    // member-chain reads, just whole-value pass-through. Since the
    // visitor only records full-chain observations (and a bare
    // tainted ident at a sink writes the whole shape's xtaint to
    // Tainted), the canonicalize result here is `Some(Tainted/Bot)`
    // — the param itself is whole-tainted with no sub-structure.
    let whole = lib.exports.get("createWhole").expect("createWhole");
    let whole_param = whole.params.first().expect("one param");
    let whole_shape = whole_param
        .param_shape
        .as_ref()
        .expect("whole-value flow records a top-level Tainted cell");
    assert!(matches!(whole_shape.xtaint, Xtaint::Tainted(_)));
    assert_eq!(whole_shape.shape, Shape::Bot);
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

/// Post-OSS-validation precision refinement (2026-05-11). The
/// `publicEmbed` and `validatorOutput` cases must not fire (the FPs
/// from dub's `referrals-token` and `shopify/order-paid`); the
/// `compoundLeak` and `apiKeyFromEnv` cases must still fire (true
/// positives the refinement must not over-suppress). Together they
/// pin both boundaries of the heuristic.
#[test]
fn secret_to_response_precision_boundaries() {
    let path = fixtures_root().join("flow-secret-to-response/precision-boundaries/lib.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/secret-to-response")
        .collect();

    // Suppressed cases: no finding may reference these function spans.
    // The fixture's source-line layout makes a span-based filter brittle,
    // so we filter by message content instead — the rule's message embeds
    // the bound identifier name (e.g. "secret-shaped value `publicToken`").
    let mentions = |needle: &str| -> bool {
        findings
            .iter()
            .any(|f| f.message.contains(&format!("`{needle}`")))
    };

    // CASE 1: public-prefix suppression.
    assert!(
        !mentions("publicToken"),
        "publicToken should be suppressed by public-prefix heuristic; got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
    assert!(
        !mentions("embedToken"),
        "embedToken should be suppressed by public-prefix heuristic; got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );

    // CASE 2: validator-output suppression. sessionToken/apiToken from
    // a parser-output destructure must not fire — the values are
    // parsed user input, not stored secrets.
    let from_validator_case = findings
        .iter()
        .filter(|f| f.message.contains("sessionToken") || f.message.contains("apiToken"))
        .count();
    // CASE 3 also uses `sessionToken`, so we need to distinguish: the
    // validator case's two bindings shouldn't BOTH appear. The cleanest
    // discriminator is "if validator suppression worked, the only
    // tainted `sessionToken` finding came from CASE 3 (one occurrence).
    // If validator suppression failed, CASE 2 would also fire, giving
    // two `sessionToken` findings.
    let session_token_count = findings
        .iter()
        .filter(|f| f.message.contains("`sessionToken`"))
        .count();
    assert_eq!(
        session_token_count,
        1,
        "expected exactly one sessionToken finding (CASE 3 only); CASE 2's \
         validator-output sessionToken must be suppressed. got {from_validator_case} matching, \
         all findings: {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
    // apiToken appears only in CASE 2; with validator suppression it
    // should fire zero times.
    assert!(
        !mentions("apiToken"),
        "apiToken from validator output must be suppressed; got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );

    // CASE 3 + CASE 4: true positives still fire.
    assert!(
        mentions("sessionToken") || mentions("refreshToken"),
        "compoundLeak() should fire on sessionToken/refreshToken (no public \
         prefix, no validator output); got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
    assert!(
        mentions("apiKey"),
        "apiKeyFromEnv() should fire on `apiKey` (assigned from \
         process.env.STRIPE_SECRET_KEY); got {:?}",
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

#[test]
fn ssrf_via_fetch_bad_fixture_fires() {
    let path = fixtures_root().join("flow-ssrf-via-fetch/bad.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/ssrf-via-fetch")
        .collect();
    let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
    assert_eq!(
        findings.len(),
        7,
        "bad.ts has 7 SSRF cases (4 full-SSRF + 3 path-injection); got {}: {:?}",
        findings.len(),
        messages,
    );
    for f in &findings {
        assert_eq!(f.span.file, path);
    }
    // Severity tier split: 4 High (CASES 1-4, full SSRF) + 3
    // Medium (CASE 5 literal-host-pinned, CASE 6 env-host-pinned,
    // CASE 7 env-host-pinned via binding).
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    assert_eq!(
        high, 4,
        "expected 4 High-severity SSRF findings, got {high}"
    );
    assert_eq!(
        medium, 3,
        "expected 3 Medium-severity path-injection findings, got {medium}"
    );
}

#[test]
fn ssrf_via_fetch_good_fixture_silent() {
    let path = fixtures_root().join("flow-ssrf-via-fetch/good.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/ssrf-via-fetch")
        .collect();
    assert!(
        findings.is_empty(),
        "good.ts has only hardcoded/env URLs — expected zero ssrf findings, got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}

#[test]
fn ssrf_via_fetch_cross_file_bad_fires() {
    // Slice 2 — the fetch sink lives in `./lib.ts`, not in the route.
    // The extract pass must summarise `forwardProxy(target)` with
    // `reaches_fetch_sink_unsanitized = true` on param 0, and the
    // run pass must emit a finding on `route.ts` at the call site.
    let dir = fixtures_root().join("flow-ssrf-via-fetch/cross-file-bad");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/ssrf-via-fetch")
        .collect();
    let route_path = dir.join("route.ts");
    let cross_file_finding = findings
        .iter()
        .find(|f| f.span.file == route_path && f.message.contains("forwardProxy"));
    assert!(
        cross_file_finding.is_some(),
        "expected a cross-file SSRF finding on route.ts referencing forwardProxy; got: {:?}",
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
    assert_eq!(cross_file_finding.unwrap().severity, Severity::High);
}

#[test]
fn ssrf_via_fetch_three_level_chain_bad_fires() {
    // route → service → client → fetch. Slice 2's iterative summary
    // computation must propagate `reaches_fetch_sink_unsanitized`
    // up through both summary layers in lock-step. The route's call
    // site is the finding location.
    let dir = fixtures_root().join("flow-ssrf-via-fetch/chain-bad");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/ssrf-via-fetch")
        .collect();
    let route_path = dir.join("route.ts");
    assert!(
        findings
            .iter()
            .any(|f| f.span.file == route_path && f.message.contains("fetchExternal")),
        "expected a finding on route.ts referencing fetchExternal; got: {:?}",
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn ssrf_via_fetch_three_level_chain_good_silent() {
    // Same chain shape as chain-bad, but the leaf `client.doFetch`
    // validates the URL host against an allow-list. The simulation
    // sees the early-throw guard, drops the reach flag at the leaf,
    // and the absence must propagate up through service.ts and
    // route.ts.
    let dir = fixtures_root().join("flow-ssrf-via-fetch/chain-good");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/ssrf-via-fetch")
        .collect();
    assert!(
        findings.is_empty(),
        "expected zero ssrf findings on chain-good/, got: {:?}",
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn ssrf_via_fetch_cross_file_good_silent() {
    // Same call shape as cross-file-bad, but the helper validates
    // the host against an allow-list before calling fetch. The
    // simulator must observe the early-return guard and drop the
    // `reaches_fetch_sink_unsanitized` flag, leaving the route's
    // call site silent.
    let dir = fixtures_root().join("flow-ssrf-via-fetch/cross-file-good");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/ssrf-via-fetch")
        .collect();
    assert!(
        findings.is_empty(),
        "expected zero ssrf findings on cross-file-good/, got: {:?}",
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn redirect_open_bad_fixture_fires() {
    let path = fixtures_root().join("flow-redirect-open/bad.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/redirect-open")
        .collect();
    let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
    assert_eq!(
        findings.len(),
        4,
        "bad.ts has 4 open-redirect cases (NextResponse.redirect, bare redirect, res.redirect, Response.redirect); got {}: {:?}",
        findings.len(),
        messages,
    );
    for f in &findings {
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.span.file, path);
    }
}

#[test]
fn redirect_open_good_fixture_silent() {
    let path = fixtures_root().join("flow-redirect-open/good.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/redirect-open")
        .collect();
    assert!(
        findings.is_empty(),
        "good.ts has only hardcoded/env URLs and allow-list-protected redirects — expected zero redirect-open findings, got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}

#[test]
fn redirect_open_cross_file_bad_fires() {
    // Slice 2 — the redirect sink lives in `./lib.ts`. The extract
    // pass must summarise `loginRedirect(target)` with
    // `reaches_redirect_sink_unsanitized = true` on param 0, and
    // the run pass must emit a finding on `route.ts` at the call
    // site.
    let dir = fixtures_root().join("flow-redirect-open/cross-file-bad");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/redirect-open")
        .collect();
    let route_path = dir.join("route.ts");
    let cross_file_finding = findings
        .iter()
        .find(|f| f.span.file == route_path && f.message.contains("loginRedirect"));
    assert!(
        cross_file_finding.is_some(),
        "expected a cross-file open-redirect finding on route.ts referencing loginRedirect; got: {:?}",
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
    assert_eq!(cross_file_finding.unwrap().severity, Severity::High);
}

#[test]
fn redirect_open_cross_file_good_silent() {
    // Same call shape as cross-file-bad, but the helper validates
    // the host against an allow-list before redirecting. The
    // simulator must observe the early-return guard and drop the
    // `reaches_redirect_sink_unsanitized` flag, leaving the route's
    // call site silent.
    let dir = fixtures_root().join("flow-redirect-open/cross-file-good");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/redirect-open")
        .collect();
    assert!(
        findings.is_empty(),
        "expected zero redirect-open findings on cross-file-good/, got: {:?}",
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn path_traversal_bad_fixture_fires() {
    let path = fixtures_root().join("flow-path-traversal/bad.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/path-traversal")
        .collect();
    let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
    assert_eq!(
        findings.len(),
        5,
        "bad.ts has 5 path-traversal cases (readFileSync, fs.promises.readFile, writeFile, createReadStream, unlink); got {}: {:?}",
        findings.len(),
        messages,
    );
    for f in &findings {
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.span.file, path);
    }
}

#[test]
fn path_traversal_good_fixture_silent() {
    let path = fixtures_root().join("flow-path-traversal/good.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/path-traversal")
        .collect();
    assert!(
        findings.is_empty(),
        "good.ts has only hardcoded/env paths — expected zero path-traversal findings, got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}

#[test]
fn prompt_injection_bad_fixture_fires() {
    let path = fixtures_root().join("flow-prompt-injection/bad.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/prompt-injection")
        .collect();
    let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
    assert_eq!(
        findings.len(),
        5,
        "bad.ts has 5 prompt-injection cases (OpenAI chat user, system+user, Responses input, Anthropic messages, template wrap); got {}: {:?}",
        findings.len(),
        messages,
    );
    for f in &findings {
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.span.file, path);
    }
}

#[test]
fn prompt_injection_good_fixture_silent() {
    let path = fixtures_root().join("flow-prompt-injection/good.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/prompt-injection")
        .collect();
    assert!(
        findings.is_empty(),
        "good.ts has only hardcoded / env / non-prompt body usage — expected zero prompt-injection findings, got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}

#[test]
fn xss_via_dangerously_set_inner_html_bad_fixture_fires() {
    let path = fixtures_root().join("flow-xss-via-dangerously-set-inner-html/bad.tsx");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/xss-via-dangerously-set-inner-html")
        .collect();
    let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
    assert_eq!(
        findings.len(),
        7,
        "bad.tsx has 7 XSS cases (req.body, req.json body, template wrap, destructured binding, Hono c.req.json, searchParams direct, searchParams via binding); got {}: {:?}",
        findings.len(),
        messages,
    );
    for f in &findings {
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.span.file, path);
    }
}

#[test]
fn command_injection_via_exec_bad_fixture_fires() {
    let path = fixtures_root().join("flow-command-injection-via-exec/bad.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/command-injection-via-exec")
        .collect();
    let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
    assert_eq!(
        findings.len(),
        6,
        "bad.ts has 6 command-injection cases (exec template, execSync template, execFile binary, spawn binary, cp.exec, exec with searchParams binding); got {}: {:?}",
        findings.len(),
        messages,
    );
    for f in &findings {
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.span.file, path);
    }
}

#[test]
fn command_injection_via_exec_good_fixture_silent() {
    let path = fixtures_root().join("flow-command-injection-via-exec/good.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/command-injection-via-exec")
        .collect();
    assert!(
        findings.is_empty(),
        "good.ts covers hardcoded / env / execFile-with-literal-binary — expected zero command-injection findings, got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}

#[test]
fn command_injection_via_exec_cross_file_bad_fires() {
    // Slice 2 — the child_process call lives in `./lib.ts`, not in
    // the route. The extract pass must summarise
    // `convertVideo(input)` with `reaches_exec_sink_unsanitized =
    // true` on param 0, and the run pass must emit a Critical
    // finding on `route.ts` at the call site.
    let dir = fixtures_root().join("flow-command-injection-via-exec/cross-file-bad");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/command-injection-via-exec")
        .collect();
    let route_path = dir.join("route.ts");
    let cross_file_finding = findings
        .iter()
        .find(|f| f.span.file == route_path && f.message.contains("convertVideo"));
    assert!(
        cross_file_finding.is_some(),
        "expected a cross-file command-injection finding on route.ts referencing convertVideo; got: {:?}",
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
    assert_eq!(cross_file_finding.unwrap().severity, Severity::Critical);
}

#[test]
fn command_injection_via_exec_cross_file_good_silent() {
    // Same call shape as cross-file-bad, but the helper uses
    // `execFile` with a hardcoded binary path and the input passed
    // as an argv element. The simulator must not record any sink
    // reach for the param, so the route's call-site finding stays
    // silent.
    let dir = fixtures_root().join("flow-command-injection-via-exec/cross-file-good");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/command-injection-via-exec")
        .collect();
    assert!(
        findings.is_empty(),
        "expected zero command-injection findings on cross-file-good/, got: {:?}",
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn sql_injection_bad_fixture_fires() {
    let path = fixtures_root().join("flow-sql-injection/bad.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/sql-injection")
        .collect();
    let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
    assert_eq!(
        findings.len(),
        5,
        "bad.ts has 5 SQL-injection cases ($queryRawUnsafe ORDER BY, $executeRawUnsafe UPDATE, Drizzle sql.raw, pool.query template wrap, $queryRawUnsafe with searchParams); got {}: {:?}",
        findings.len(),
        messages,
    );
    for f in &findings {
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.span.file, path);
    }
}

#[test]
fn sql_injection_good_fixture_silent() {
    let path = fixtures_root().join("flow-sql-injection/good.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/sql-injection")
        .collect();
    assert!(
        findings.is_empty(),
        "good.ts covers parameterised paths + typed Prisma API — expected zero SQL-injection findings, got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}

#[test]
fn sql_injection_cross_file_bad_fires() {
    // Slice 2 — the raw-SQL sink lives in `./lib.ts`, not in the
    // route. The extract pass must summarise `findUserBySlug(slug)`
    // with `reaches_sql_sink_unsanitized = true` on param 0, and
    // the run pass must emit a Critical finding on `route.ts` at
    // the call site.
    let dir = fixtures_root().join("flow-sql-injection/cross-file-bad");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/sql-injection")
        .collect();
    let route_path = dir.join("route.ts");
    let cross_file_finding = findings
        .iter()
        .find(|f| f.span.file == route_path && f.message.contains("findUserBySlug"));
    assert!(
        cross_file_finding.is_some(),
        "expected a cross-file SQL-injection finding on route.ts referencing findUserBySlug; got: {:?}",
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
    assert_eq!(cross_file_finding.unwrap().severity, Severity::Critical);
}

#[test]
fn sql_injection_cross_file_good_silent() {
    // Same call shape as cross-file-bad, but the helper uses
    // Prisma's parameterised tagged-template `$queryRaw`. The
    // simulator must not record any sink reach for the param, so
    // the route's call-site finding stays silent.
    let dir = fixtures_root().join("flow-sql-injection/cross-file-good");
    let findings: Vec<_> = scan_dir(&dir)
        .into_iter()
        .filter(|f| f.rule_id == "flow/sql-injection")
        .collect();
    assert!(
        findings.is_empty(),
        "expected zero SQL-injection findings on cross-file-good/, got: {:?}",
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn xss_via_dangerously_set_inner_html_good_fixture_silent() {
    let path = fixtures_root().join("flow-xss-via-dangerously-set-inner-html/good.tsx");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/xss-via-dangerously-set-inner-html")
        .collect();
    assert!(
        findings.is_empty(),
        "good.tsx covers hardcoded / env / DOMPurify / sanitize-html / body-but-not-html — expected zero XSS findings, got {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}

#[test]
fn unvalidated_body_to_db_per_field_sanitisation_only_control_fires() {
    // v0.2.13 precision win. The fixture has 3 cases:
    //   CASE 1: parse(body.id); use body.id only            → no fire
    //   CASE 2: parse(body.id); use body.id AND body.name   → fires on body.name
    //   CASE 3: parse(body.user.email); use body.user.email → no fire (deep path)
    let path = fixtures_root().join("flow-unvalidated-body-to-db/per-field-sanitisation.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db")
        .collect();
    assert_eq!(
        findings.len(),
        1,
        "expected exactly 1 finding (CASE 2 control); got {}: {:?}",
        findings.len(),
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn unvalidated_body_to_db_higher_order_all_cases_fire() {
    // Audit fix #2 (v0.2.11). Higher-order callback patterns —
    // `.then(body => …)`, `.map(item => …)`, `.forEach(item => …)`,
    // and chained `.filter(p).forEach(item => …)` — previously
    // missed because the flagship's custom statement-walk never
    // recursed into callback bodies and the callback param was
    // never pre-tainted. All 4 should fire after v0.2.11.
    let path = fixtures_root().join("flow-unvalidated-body-to-db/higher-order-bad.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db")
        .collect();
    assert_eq!(
        findings.len(),
        4,
        "expected all 4 higher-order cases to fire; got {}: {:?}",
        findings.len(),
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn unvalidated_body_to_db_branch_merge_all_cases_fire() {
    // Audit fix #1 (v0.2.10): the visitor previously walked
    // if/else sequentially and missed cases where one branch left
    // a binding tainted. All three cases below — taint preserved
    // in the no-if path; taint reintroduced in the alternate;
    // taint introduced in the consequent but cleared in the
    // alternate — should now fire.
    let path = fixtures_root().join("flow-unvalidated-body-to-db/branch-merge-bad.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/unvalidated-body-to-db")
        .collect();
    assert_eq!(
        findings.len(),
        3,
        "expected all 3 branch-merge cases to fire; got {}: {:?}",
        findings.len(),
        findings
            .iter()
            .map(|f| (&f.span.file, &f.message))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn suppress_inline_drops_matching_rule_only() {
    // inline.ts has two `exec(...)` calls that would normally fire
    // `flow/command-injection-via-exec`. Case 1 is preceded by a
    // matching suppression marker and should NOT fire. Case 2 is
    // preceded by a marker for a different rule id and SHOULD fire.
    let path = fixtures_root().join("suppress-comments/inline.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/command-injection-via-exec")
        .collect();
    assert_eq!(
        findings.len(),
        1,
        "expected exactly one command-injection finding (case 2 only); got {}: {:?}",
        findings.len(),
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}

#[test]
fn suppress_file_level_drops_all_findings_for_rule() {
    // file-level.ts has a `// stryx-disable
    // flow/command-injection-via-exec` at the top. Both `exec(...)`
    // calls inside the file should be silenced.
    let path = fixtures_root().join("suppress-comments/file-level.ts");
    let findings: Vec<_> = scan_file(&path)
        .into_iter()
        .filter(|f| f.rule_id == "flow/command-injection-via-exec")
        .collect();
    assert!(
        findings.is_empty(),
        "file-level disable should silence every command-injection finding in the file; got: {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>(),
    );
}
