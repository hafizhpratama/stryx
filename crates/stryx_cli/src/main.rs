use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dashmap::DashMap;
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use stryx_ast::{parse, Allocator};
use stryx_core::{Finding, Severity};
use stryx_index::ProjectIndex;
use stryx_reporter::{write_report, ReportFormat};
use stryx_rules::{builtin_rules, RuleContext, RuleRegistry};

#[derive(Parser, Debug)]
#[command(
    name = "stryx",
    version,
    about = "Sees what your AI missed — across files.",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan a directory or file for AI failure patterns.
    Scan {
        /// Path to scan. Defaults to the current directory.
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format: human or json.
        #[arg(long, default_value = "human")]
        format: String,

        /// Minimum severity that triggers a non-zero exit code.
        #[arg(long, default_value = "high")]
        fail_on: String,
    },
    /// Print version information as JSON.
    Version,
    /// List all built-in rules.
    Rules,
}

fn main() -> ExitCode {
    init_tracing();
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Scan {
            path,
            format,
            fail_on,
        } => cmd_scan(&path, &format, &fail_on),
        Command::Version => cmd_version(),
        Command::Rules => cmd_rules(),
    };

    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("stryx: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "warn".into());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

fn cmd_version() -> Result<ExitCode> {
    let out = serde_json::json!({
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "engine": "stryx",
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(ExitCode::SUCCESS)
}

fn cmd_rules() -> Result<ExitCode> {
    let registry = builtin_rules();
    for rule in registry.rules() {
        let m = rule.meta();
        println!("{:<32} {:<8}  {}", m.id, m.default_severity, m.description);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_scan(path: &Path, format_str: &str, fail_on: &str) -> Result<ExitCode> {
    let format = ReportFormat::parse(format_str)
        .with_context(|| format!("unknown --format value: {format_str}"))?;
    let fail_threshold = parse_severity(fail_on)
        .with_context(|| format!("unknown --fail-on value: {fail_on}"))?;

    let registry = Arc::new(builtin_rules());
    let files = collect_targets(path)?;

    if files.is_empty() {
        eprintln!("stryx: no TypeScript/JavaScript files found at {}", path.display());
        return Ok(ExitCode::SUCCESS);
    }

    // Capture sources keyed by path so the reporter can resolve line/col
    // without re-reading from disk.
    let sources: Arc<DashMap<PathBuf, String>> = Arc::new(DashMap::new());

    // Pass 1 — iterative extract. On each round every rule sees the
    // previous round's ProjectIndex, so summaries that depend on
    // cross-file calls converge through multi-level chains (controller →
    // service → repository). Capped at MAX_ITER as a safety net; in
    // practice TS apps converge in 2–4 rounds because reachability is
    // monotonic.
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

    // Pass 2 — run: each rule sees the merged index and produces findings.
    let findings: Vec<Finding> = files
        .par_iter()
        .flat_map_iter(|file| run_file(file, &registry, &sources, &project_index))
        .collect();

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    write_report(
        &mut handle,
        &findings,
        |p| sources.get(p).map(|s| s.clone()),
        format,
    )?;

    let max_severity = findings.iter().map(|f| f.severity).max();
    let should_fail = matches!(max_severity, Some(s) if s >= fail_threshold);
    Ok(if should_fail { ExitCode::from(1) } else { ExitCode::SUCCESS })
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

/// Pass 1: parse the file and let each rule contribute a per-file
/// summary. The previous round's `ProjectIndex` is exposed so summaries
/// can depend on cross-file calls already known to sink.
///
/// On the first round the source is read from disk and cached; later
/// rounds reuse the cached source, so the iterative loop only pays for
/// re-parsing each file (cheap with oxc).
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
/// to the database. Monotonic across iterations — only flips false→true
/// — so a fixed point is reached in at most call-graph-depth rounds.
fn sink_param_count(index: &ProjectIndex) -> usize {
    index
        .files()
        .flat_map(|f| f.exports.values())
        .flat_map(|e| e.params.iter())
        .filter(|p| p.reaches_db_sink_unsanitized)
        .count()
}

/// Pass 2: re-parse the file and run rules with access to the merged
/// project index. Source comes from the cache populated in pass 1.
fn run_file(
    file: &Path,
    registry: &Arc<RuleRegistry>,
    sources: &Arc<DashMap<PathBuf, String>>,
    index: &Arc<ProjectIndex>,
) -> Vec<Finding> {
    let source = match sources.get(file) {
        Some(s) => s.clone(),
        None => return Vec::new(), // pass 1 declined this file (read or parse error)
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

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" | "med" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" | "crit" => Some(Severity::Critical),
        _ => None,
    }
}
