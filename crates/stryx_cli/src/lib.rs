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
use stryx_index::ProjectIndex;
use stryx_rules::{RuleContext, RuleRegistry, builtin_rules};

/// Output of a scan. `findings` is the merged set of all rule
/// findings across the file tree; `sources` is the captured file
/// content keyed by absolute path so callers (CLI, JSON reporter,
/// SARIF reporter, GitHub annotation reporter) can resolve
/// line/column positions without re-reading from disk.
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub sources: HashMap<PathBuf, String>,
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

    if files.is_empty() {
        return Ok(ScanResult {
            findings: Vec::new(),
            sources: HashMap::new(),
        });
    }

    let sources: Arc<DashMap<PathBuf, String>> = Arc::new(DashMap::new());

    // Pass 1 — iterative extract. On each round every rule sees the
    // previous round's ProjectIndex, so summaries that depend on
    // cross-file calls converge through multi-level chains
    // (controller → service → repository). Capped at MAX_ITER as a
    // safety net; in practice TS apps converge in 2–4 rounds because
    // reachability is monotonic.
    const MAX_ITER: usize = 10;
    let mut project_index = ProjectIndex::new();
    let mut prev_signal = 0usize;
    for round in 0..MAX_ITER {
        let prev = Arc::new(project_index);
        let summaries: Vec<stryx_index::FileSummary> = files
            .par_iter()
            .flat_map_iter(|file| extract_file(file, &registry, &sources, &prev))
            .collect();
        let mut next = ProjectIndex::new();
        for summary in summaries {
            next.insert_file(summary);
        }
        next.finalize();
        let signal = sink_param_count(&next);
        tracing::debug!(round, signal, "extract round");
        project_index = next;
        if round > 0 && signal == prev_signal {
            break;
        }
        prev_signal = signal;
    }
    let project_index = Arc::new(project_index);

    // Pass 2 — run.
    let findings: Vec<Finding> = files
        .par_iter()
        .flat_map_iter(|file| run_file(file, &registry, &sources, &project_index))
        .collect();

    let sources_out: HashMap<PathBuf, String> = sources
        .iter()
        .map(|entry| (entry.key().clone(), entry.value().clone()))
        .collect();

    Ok(ScanResult {
        findings,
        sources: sources_out,
    })
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
    };
    let mut out = Vec::new();
    for rule in registry.rules() {
        if let Some(summary) = rule.extract(&ctx) {
            out.push(summary);
        }
    }
    out
}

/// Convergence signal: total number of (file, exported-fn, param)
/// triples whose summary marks them as sinking unsanitised body taint
/// to the database. Monotonic across iterations — only flips
/// false→true — so a fixed point is reached in at most call-graph-
/// depth rounds.
fn sink_param_count(index: &ProjectIndex) -> usize {
    index
        .files()
        .flat_map(|f| f.exports.values())
        .flat_map(|e| e.params.iter())
        .filter(|p| p.reaches_db_sink_unsanitized)
        .count()
}

fn run_file(
    file: &Path,
    registry: &Arc<RuleRegistry>,
    sources: &Arc<DashMap<PathBuf, String>>,
    index: &Arc<ProjectIndex>,
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
    };
    let mut findings = Vec::new();
    for rule in registry.rules() {
        findings.extend(rule.run(&ctx));
    }
    findings
}
