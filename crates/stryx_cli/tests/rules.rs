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
