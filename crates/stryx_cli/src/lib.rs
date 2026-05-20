//! Library entry point for the Stryx engine. The CLI binary in
//! `main.rs` is a thin clap wrapper around the [`scan`] function
//! exposed here; bindings (napi, future python, etc.) consume the
//! same API so the two-pass extract→run pipeline lives in one place.

use anyhow::{Context, Result};
use dashmap::DashMap;
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use stryx_ast::{Allocator, parse};
use stryx_core::Finding;
use stryx_index::jsonc::strip_jsonc;
use stryx_index::profile::{self, ProjectProfile};
use stryx_index::{PathAlias, ProjectIndex};
use stryx_rules::adapters::{AdapterRegistry, EnabledAdapters};
use stryx_rules::{RuleContext, RuleRegistry, builtin_rules};

mod suppress;
pub use suppress::filter_suppressed;

/// Output of a scan. `findings` is the merged set of all rule
/// findings across the file tree; `sources` is the captured file
/// content keyed by absolute path so callers (CLI, JSON reporter,
/// SARIF reporter, GitHub annotation reporter) can resolve
/// line/column positions without re-reading from disk.
/// `profile` captures detected stack evidence from package.json,
/// lockfiles, and config files (no source parsing required).
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub sources: HashMap<PathBuf, String>,
    pub profile: ProjectProfile,
}

/// Scan a path. Walks `path` (gitignore-aware via the `ignore` crate)
/// for TypeScript / JavaScript files, parses each in parallel, runs
/// the iterative two-pass extract→run pipeline, and returns the
/// findings.
///
/// Returns an empty result when the path contains no scannable
/// files. Parse errors and unreadable files are logged via `tracing`
/// and skipped, not propagated.
pub fn scan(path: &Path) -> Result<ScanResult> {
    let registry = Arc::new(builtin_rules());
    let files =
        collect_targets(path).with_context(|| format!("collect targets at {}", path.display()))?;

    // Build the project profile once at scan start. Cheap (reads at
    // most ~10 files: package.json + lockfiles + a few configs) and
    // independent of the per-file extract loop, so it runs unconditionally
    // — even an empty-target scan returns whatever profile evidence
    // exists, which is the right answer for `scan --format=json` on a
    // workspace with a package.json but no committed sources yet.
    let profile = profile::detect(path);

    // Resolve which adapters apply to the detected profile. Owned by
    // this scope so the `&EnabledAdapters` threaded through extract /
    // run lives for the full pipeline; the registry itself is built
    // from `&'static` adapter references so cloning the resolved view
    // per round would be wasteful and is unnecessary.
    let adapters_registry = AdapterRegistry::builtin();
    let enabled_adapters = adapters_registry.enabled_for(&profile);

    if files.is_empty() {
        return Ok(ScanResult {
            findings: Vec::new(),
            sources: HashMap::new(),
            profile,
        });
    }

    let sources: Arc<DashMap<PathBuf, String>> = Arc::new(DashMap::new());

    // Read tsconfig.json (or jsconfig.json) at the scan root once
    // and feed the path aliases into every iteration's index. Most
    // Next.js apps ship with a `@/*` alias by default; without
    // this, every cross-file flow through `@/lib/...` is silently
    // unresolved.
    let path_aliases = read_tsconfig_path_aliases(path);

    // Pass 1 — iterative extract. On each round every rule sees the
    // previous round's ProjectIndex, so summaries that depend on
    // cross-file calls converge through multi-level chains
    // (controller → service → repository). Capped at MAX_ITER as a
    // safety net; in practice TS apps converge in 2–4 rounds because
    // reachability is monotonic.
    //
    // Convergence is detected against a *tuple* of independent
    // counts — sink-param flips, propagates-to-return flips,
    // body-validated-handler insertions, and tainted-offset growth.
    // Comparing against just the first count was the original
    // implementation, but it could declare convergence early while
    // another axis was still mid-flight, leading to silent
    // under-detection. See ADR 0004 for the contract; new summary
    // axes must be added in lockstep with their `ConvergenceSignal`
    // counterpart and a per-axis test in `mod tests` below.
    const MAX_ITER: usize = 10;
    let mut project_index = ProjectIndex::new();
    let mut prev_signal: Option<ConvergenceSignal> = None;
    let mut converged = false;
    let mut last_signal = ConvergenceSignal::default();
    for round in 0..MAX_ITER {
        let prev = Arc::new(project_index);
        let summaries: Vec<stryx_index::FileSummary> = files
            .par_iter()
            .flat_map_iter(|file| extract_file(file, &registry, &sources, &prev, &enabled_adapters))
            .collect();
        let mut next = ProjectIndex::new();
        for summary in summaries {
            next.insert_file(summary);
        }
        next.set_path_aliases(path_aliases.clone());
        next.finalize();
        let signal = convergence_signal(&next);
        tracing::debug!(round, ?signal, "extract round");
        last_signal = signal;
        project_index = next;
        if let Some(prev) = &prev_signal
            && *prev == signal
        {
            converged = true;
            break;
        }
        prev_signal = Some(signal);
    }
    if !converged {
        // Hit the iteration cap without reaching a fixed point. The
        // analysis is unsound at this point — flows that needed >10
        // hops are silently under-approximated. Surface this so the
        // user knows; future versions will emit explicit
        // UncertainZones for LLM escalation here.
        tracing::warn!(
            max_iter = MAX_ITER,
            ?last_signal,
            "extract pass exited via iteration cap without reaching a fixed point — \
             call chains deeper than {MAX_ITER} hops may be under-approximated. \
             Set RUST_LOG=stryx_cli=debug to see per-round signals."
        );
    }
    let project_index = Arc::new(project_index);

    // Pass 2 — run.
    let findings: Vec<Finding> = files
        .par_iter()
        .flat_map_iter(|file| {
            run_file(file, &registry, &sources, &project_index, &enabled_adapters)
        })
        .collect();

    let sources_out: HashMap<PathBuf, String> = sources
        .iter()
        .map(|entry| (entry.key().clone(), entry.value().clone()))
        .collect();

    // Pass 3 — drop findings whose source line is covered by a
    // `// stryx-disable-next-line <rule-id>` or `// stryx-disable
    // <rule-id>` comment. Centralized here so each rule visitor
    // stays ignorant of suppression-comment shape.
    let findings = filter_suppressed(findings, &sources_out);

    Ok(ScanResult {
        findings,
        sources: sources_out,
        profile,
    })
}

/// Read `tsconfig.json` or `jsconfig.json` at the scan root and
/// extract `compilerOptions.paths` as a list of [`PathAlias`].
/// Returns an empty list if no config exists, can't be parsed, or
/// declares no paths. Errors are logged at `warn` and not
/// propagated — a malformed tsconfig shouldn't fail the scan.
///
/// `baseUrl` is honoured (defaulting to `.`) so replacements are
/// rooted at the right directory. Both `tsconfig.json` and
/// `jsconfig.json` are checked; the first that exists wins.
fn read_tsconfig_path_aliases(scan_root: &Path) -> Vec<PathAlias> {
    let root = if scan_root.is_dir() {
        scan_root
    } else {
        scan_root.parent().unwrap_or(Path::new("."))
    };
    for name in ["tsconfig.json", "jsconfig.json"] {
        let path = root.join(name);
        if path.exists() {
            match parse_tsconfig_paths(&path) {
                Ok(aliases) => return aliases,
                Err(err) => {
                    tracing::warn!(?path, %err, "failed to parse tsconfig; skipping path aliases");
                    return Vec::new();
                }
            }
        }
    }
    Vec::new()
}

fn parse_tsconfig_paths(tsconfig_path: &Path) -> Result<Vec<PathAlias>> {
    let raw = std::fs::read_to_string(tsconfig_path)
        .with_context(|| format!("read {}", tsconfig_path.display()))?;
    // tsconfig allows JSON-with-comments; serde_json doesn't. Strip
    // line comments (`// …`) and block comments (`/* … */`) before
    // parsing. Trailing commas are also allowed by tsc but rejected
    // by serde_json; we make a best effort to strip those too.
    let cleaned = strip_jsonc(&raw);
    let value: serde_json::Value = serde_json::from_str(&cleaned)
        .with_context(|| format!("parse {}", tsconfig_path.display()))?;
    let opts = match value.get("compilerOptions") {
        Some(o) => o,
        None => return Ok(Vec::new()),
    };
    let base_url = opts.get("baseUrl").and_then(|v| v.as_str()).unwrap_or(".");
    let base_root = tsconfig_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(base_url);
    let paths_obj = match opts.get("paths").and_then(|v| v.as_object()) {
        Some(p) => p,
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for (pattern, replacements) in paths_obj {
        let Some(replacements_arr) = replacements.as_array() else {
            continue;
        };
        let replacements: Vec<PathBuf> = replacements_arr
            .iter()
            .filter_map(|v| v.as_str())
            .map(|r| base_root.join(r))
            .collect();
        if replacements.is_empty() {
            continue;
        }
        out.push(PathAlias {
            pattern: pattern.clone(),
            replacements,
        });
    }
    Ok(out)
}

fn collect_targets(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let walker = WalkBuilder::new(root).follow_links(false).build();
    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!(%err, "skip unreadable entry");
                continue;
            }
        };
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let p = entry.path();
        if has_ts_extension(p) {
            out.push(p.to_path_buf());
        }
    }
    Ok(out)
}

fn has_ts_extension(p: &Path) -> bool {
    matches!(
        p.extension().and_then(|e| e.to_str()),
        Some("ts" | "tsx" | "mts" | "cts" | "js" | "jsx" | "mjs" | "cjs"),
    )
}

fn extract_file(
    file: &Path,
    registry: &Arc<RuleRegistry>,
    sources: &Arc<DashMap<PathBuf, String>>,
    prev_index: &Arc<ProjectIndex>,
    adapters: &EnabledAdapters,
) -> Vec<stryx_index::FileSummary> {
    let source = if let Some(cached) = sources.get(file) {
        cached.clone()
    } else {
        match std::fs::read_to_string(file) {
            Ok(s) => {
                sources.insert(file.to_path_buf(), s.clone());
                s
            }
            Err(err) => {
                tracing::warn!(?file, %err, "skip unreadable file");
                return Vec::new();
            }
        }
    };

    let allocator = Allocator::default();
    let parsed = match parse(&allocator, file, &source) {
        Ok(p) => p,
        Err(err) => {
            tracing::warn!(?file, %err, "parse error");
            return Vec::new();
        }
    };

    let ctx = RuleContext {
        file: &parsed,
        index: Some(prev_index),
        adapters: Some(adapters),
    };
    let mut out = Vec::new();
    for rule in registry.rules() {
        if let Some(summary) = rule.extract(&ctx) {
            out.push(summary);
        }
    }
    out
}

/// Per-round convergence signal — a tuple of independent counts so
/// the loop doesn't declare convergence early while one flag is
/// still propagating but the others happen to land on the same
/// total. All counts are monotone non-decreasing under the taint
/// sub-lattice, so equality across two consecutive rounds is a
/// sound fixed-point witness.
///
/// **Contract (ADR 0004):** every summary axis that can change
/// across iterations must be reflected here, otherwise the loop
/// silently under-detects via the missing axis. When you add a new
/// axis to [`ParamFlow`] or [`ExportedFunctionSummary`], add a
/// matching count below — even if the existing counts subsume it
/// in practice, the redundancy is the safety net.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ConvergenceSignal {
    sink_params: usize,
    propagating_params: usize,
    body_validated_handlers: usize,
    /// Per ADR 0006 slice 2 — total `tainted_offsets` length across
    /// all summarised params. Tracked separately from `sink_params`
    /// because a param's offset list can grow without flipping the
    /// boolean (e.g., a cross-file callee resolved on round N+1
    /// surfaces additional reads at the same param).
    tainted_offset_total: usize,
    /// Per ADR 0006 slice 2.1c — total Tainted leaves across every
    /// summarised param's `param_shape` tree. Finer-grained than
    /// `tainted_offsets`: two shapes can share the same first-field
    /// set while differing on chain depth (`body.where.id` vs
    /// `body.where`). Tracked separately so the convergence loop
    /// notices shape growth even when the offset list is unchanged.
    tainted_leaf_total: usize,
    /// Slice 2 of `flow/ssrf-via-fetch` — params that reach a
    /// fetch/axios/got sink as the URL argument. Independent axis
    /// from `sink_params` (which counts DB-sink params): a callee
    /// can taint to fetch without tainting to DB, so flipping this
    /// flag across rounds is a separate convergence event.
    fetch_sink_params: usize,
    /// Slice 2 of `flow/redirect-open` — params that reach a
    /// redirect sink (NextResponse.redirect / bare redirect /
    /// res.redirect / Response.redirect) as the target URL.
    /// Independent axis from `sink_params` and `fetch_sink_params`
    /// — a helper can taint to redirect alone (e.g. an OAuth
    /// callback redirector) without touching a DB or fetch sink.
    redirect_sink_params: usize,
    /// Per ADR 0007 slice 3.1 — total Tainted leaves across every
    /// summarised param's `return_shape` tree. Mirrors
    /// `tainted_leaf_total` but for the return side. Required so the
    /// fix-point loop notices return-shape growth across iterations
    /// (an iteration can refine return shapes independently of
    /// param shapes — different axis).
    return_leaf_total: usize,
}

fn convergence_signal(index: &ProjectIndex) -> ConvergenceSignal {
    let mut sink_params = 0;
    let mut propagating_params = 0;
    let mut body_validated_handlers = 0;
    let mut tainted_offset_total = 0;
    let mut tainted_leaf_total = 0;
    let mut return_leaf_total = 0;
    let mut fetch_sink_params = 0;
    let mut redirect_sink_params = 0;
    for file in index.files() {
        for export in file.exports.values().chain(file.locals.values()) {
            for param in &export.params {
                if param.reaches_db_sink_unsanitized {
                    sink_params += 1;
                }
                if param.reaches_fetch_sink_unsanitized {
                    fetch_sink_params += 1;
                }
                if param.reaches_redirect_sink_unsanitized {
                    redirect_sink_params += 1;
                }
                if param.propagates_to_return {
                    propagating_params += 1;
                }
                tainted_offset_total += param.tainted_offsets.len();
                if let Some(shape) = &param.param_shape {
                    tainted_leaf_total += shape.count_tainted_leaves();
                }
                if let Some(shape) = &param.return_shape {
                    return_leaf_total += shape.count_tainted_leaves();
                }
            }
        }
        body_validated_handlers += file.body_validated_handlers.len();
    }
    ConvergenceSignal {
        sink_params,
        propagating_params,
        body_validated_handlers,
        tainted_offset_total,
        tainted_leaf_total,
        return_leaf_total,
        fetch_sink_params,
        redirect_sink_params,
    }
}

fn run_file(
    file: &Path,
    registry: &Arc<RuleRegistry>,
    sources: &Arc<DashMap<PathBuf, String>>,
    index: &Arc<ProjectIndex>,
    adapters: &EnabledAdapters,
) -> Vec<Finding> {
    let source = match sources.get(file) {
        Some(s) => s.clone(),
        None => return Vec::new(),
    };

    let allocator = Allocator::default();
    let parsed = match parse(&allocator, file, &source) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let ctx = RuleContext {
        file: &parsed,
        index: Some(index),
        adapters: Some(adapters),
    };
    let mut findings = Vec::new();
    for rule in registry.rules() {
        findings.extend(rule.run(&ctx));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use stryx_core::Span;
    use stryx_index::FileSummary;
    use stryx_taint::{Cell, ExportedFunctionSummary, Offset, ParamFlow, TaintLabel};

    /// Build a single-export `FileSummary` containing one param so each
    /// convergence-axis test can mutate just that one axis.
    fn fixture_with_param(p: ParamFlow) -> FileSummary {
        let mut summary = FileSummary {
            path: PathBuf::from("/virt/file.ts"),
            ..Default::default()
        };
        summary.exports.insert(
            "handler".into(),
            ExportedFunctionSummary {
                name: "handler".into(),
                params: vec![p],
                span: Span::new(PathBuf::from("/virt/file.ts"), 0, 0),
                contains_auth_check: false,
                validates_request_body: false,
            },
        );
        summary
    }

    fn signal_for(file: FileSummary) -> ConvergenceSignal {
        let mut idx = ProjectIndex::new();
        idx.insert_file(file);
        idx.finalize();
        convergence_signal(&idx)
    }

    /// ADR 0004 contract — the convergence signal must distinguish
    /// every taint-flow axis on `ParamFlow`. When you add a new
    /// boolean/collection axis, add a per-axis test here in lockstep
    /// or the fixed-point loop will silently under-detect through
    /// the missing axis.
    #[test]
    fn convergence_signal_reflects_reaches_db_sink_unsanitized() {
        let zero = signal_for(fixture_with_param(ParamFlow::default()));
        let one = signal_for(fixture_with_param(ParamFlow {
            reaches_db_sink_unsanitized: true,
            ..Default::default()
        }));
        assert_ne!(zero, one, "sink_params axis must affect the signal");
    }

    #[test]
    fn convergence_signal_reflects_propagates_to_return() {
        let zero = signal_for(fixture_with_param(ParamFlow::default()));
        let one = signal_for(fixture_with_param(ParamFlow {
            propagates_to_return: true,
            ..Default::default()
        }));
        assert_ne!(zero, one, "propagating_params axis must affect the signal");
    }

    /// Slice 2 of `flow/ssrf-via-fetch` added
    /// `reaches_fetch_sink_unsanitized`. Per ADR 0004, it must be in
    /// the convergence tuple — this test guards against the
    /// silent-under-detection regression where the loop declares
    /// convergence while a callee's fetch-sink reachability is still
    /// flipping across iterations.
    #[test]
    fn convergence_signal_reflects_reaches_fetch_sink_unsanitized() {
        let zero = signal_for(fixture_with_param(ParamFlow::default()));
        let one = signal_for(fixture_with_param(ParamFlow {
            reaches_fetch_sink_unsanitized: true,
            ..Default::default()
        }));
        assert_ne!(zero, one, "fetch_sink_params axis must affect the signal");
    }

    /// Slice 2 of `flow/redirect-open` added
    /// `reaches_redirect_sink_unsanitized`. Same ADR 0004 contract
    /// as the fetch flag — the convergence tuple must reflect it
    /// or chains through helpers that redirect (without DB or
    /// fetch sinks) will silently under-detect.
    #[test]
    fn convergence_signal_reflects_reaches_redirect_sink_unsanitized() {
        let zero = signal_for(fixture_with_param(ParamFlow::default()));
        let one = signal_for(fixture_with_param(ParamFlow {
            reaches_redirect_sink_unsanitized: true,
            ..Default::default()
        }));
        assert_ne!(
            zero, one,
            "redirect_sink_params axis must affect the signal"
        );
    }

    /// Slice 2 of ADR 0006 added `tainted_offsets`. Per ADR 0004, it
    /// must be in the convergence tuple — this test guards against
    /// the silent-under-detection regression where the loop declares
    /// convergence while a callee's offset list is still growing.
    #[test]
    fn convergence_signal_reflects_tainted_offsets() {
        let zero = signal_for(fixture_with_param(ParamFlow::default()));
        let one = signal_for(fixture_with_param(ParamFlow {
            tainted_offsets: vec![Offset::Field("id".into())],
            ..Default::default()
        }));
        assert_ne!(
            zero, one,
            "tainted_offset_total axis must affect the signal"
        );
        // Two offsets distinguishable from one — the count, not just
        // presence, is what matters.
        let two = signal_for(fixture_with_param(ParamFlow {
            tainted_offsets: vec![Offset::Field("id".into()), Offset::Field("name".into())],
            ..Default::default()
        }));
        assert_ne!(one, two, "growing offset list must shift the signal");
    }

    /// Slice 2.1c of ADR 0006 added `param_shape`. Per ADR 0004, the
    /// shape's Tainted-leaf count must be in the convergence tuple
    /// — without it, a deeper shape (e.g. `body.where.id` instead of
    /// just `body.where`) on iteration N+1 wouldn't shift the signal
    /// and the loop would falsely declare convergence.
    #[test]
    fn convergence_signal_reflects_param_shape() {
        let zero = signal_for(fixture_with_param(ParamFlow::default()));
        let one = signal_for(fixture_with_param(ParamFlow {
            param_shape: Some(Cell::tainted(vec![TaintLabel::UserInput])),
            ..Default::default()
        }));
        assert_ne!(zero, one, "tainted_leaf_total axis must affect the signal");
        // A shape with two tainted leaves is distinguishable from one
        // with a single leaf — chain growth (deeper structure) is the
        // case this guards against.
        use std::collections::BTreeMap;
        let mut deeper = BTreeMap::new();
        deeper.insert(
            Offset::Field("a".into()),
            Cell::tainted(vec![TaintLabel::UserInput]),
        );
        deeper.insert(
            Offset::Field("b".into()),
            Cell::tainted(vec![TaintLabel::UserInput]),
        );
        let deeper_shape = Cell {
            xtaint: stryx_taint::Xtaint::None,
            shape: stryx_taint::Shape::Obj(deeper),
        };
        let two = signal_for(fixture_with_param(ParamFlow {
            param_shape: Some(deeper_shape),
            ..Default::default()
        }));
        assert_ne!(one, two, "shape growth must shift the signal");
    }

    /// Slice 3.1 of ADR 0007 added `return_shape`. Per ADR 0004, it
    /// must be in the convergence tuple — without it, iteration N+1
    /// could refine a callee's return shape but the loop would
    /// declare convergence anyway.
    #[test]
    fn convergence_signal_reflects_return_shape() {
        let zero = signal_for(fixture_with_param(ParamFlow::default()));
        let one = signal_for(fixture_with_param(ParamFlow {
            return_shape: Some(Cell::tainted(vec![TaintLabel::UserInput])),
            ..Default::default()
        }));
        assert_ne!(zero, one, "return_leaf_total axis must affect the signal");
        // A return shape with two tainted leaves is distinguishable
        // from one with a single leaf — chain growth (deeper return
        // structure) is the case this guards against.
        use std::collections::BTreeMap;
        let mut deeper = BTreeMap::new();
        deeper.insert(
            Offset::Field("a".into()),
            Cell::tainted(vec![TaintLabel::UserInput]),
        );
        deeper.insert(
            Offset::Field("b".into()),
            Cell::tainted(vec![TaintLabel::UserInput]),
        );
        let deeper_shape = Cell {
            xtaint: stryx_taint::Xtaint::None,
            shape: stryx_taint::Shape::Obj(deeper),
        };
        let two = signal_for(fixture_with_param(ParamFlow {
            return_shape: Some(deeper_shape),
            ..Default::default()
        }));
        assert_ne!(one, two, "return-shape growth must shift the signal");
    }
}
