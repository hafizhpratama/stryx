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

    let findings: Vec<Finding> = files
        .par_iter()
        .flat_map_iter(|file| scan_file(file, &registry, &sources))
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

fn scan_file(
    file: &Path,
    registry: &Arc<RuleRegistry>,
    sources: &Arc<DashMap<PathBuf, String>>,
) -> Vec<Finding> {
    let source = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(?file, %err, "skip unreadable file");
            return Vec::new();
        }
    };
    sources.insert(file.to_path_buf(), source.clone());

    let allocator = Allocator::default();
    let parsed = match parse(&allocator, file, &source) {
        Ok(p) => p,
        Err(err) => {
            tracing::warn!(?file, %err, "parse error");
            return Vec::new();
        }
    };

    let ctx = RuleContext { file: &parsed };
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
