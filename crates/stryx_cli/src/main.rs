use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use stryx_cli::{ScanOptions, scan_with_options};
use stryx_core::Severity;
use stryx_reporter::{ReportFormat, ReportOptions, write_report};
use stryx_rules::builtin_rules;

/// Top-level CLI. The default invocation (no subcommand) runs a scan
/// against the current directory using the top-level flags; explicit
/// subcommands are still accepted for compatibility and for non-scan
/// operations (`version`, `rules`).
#[derive(Parser, Debug)]
#[command(
    name = "stryx",
    version,
    about = "Stack-aware security for JavaScript and TypeScript backends.",
    long_about = None,
    args_conflicts_with_subcommands = true,
)]
struct Cli {
    /// Path to scan. Defaults to the current directory.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Output format: `human` or `json`.
    #[arg(long, default_value = "human")]
    format: String,

    /// Minimum severity that triggers a non-zero exit code:
    /// `info` / `low` / `medium` / `high` / `critical`.
    #[arg(long, default_value = "high")]
    fail_on: String,

    /// Print every finding instead of representative locations per
    /// rule group. Has no effect on `--format=json` (JSON always
    /// includes the full finding list).
    #[arg(long)]
    verbose: bool,

    /// Scan only files changed since `<base>` (a git ref, branch, or
    /// commit). Useful for PR-only CI runs. Falls back to a full scan
    /// when not in a git work tree.
    #[arg(long, value_name = "BASE")]
    diff: Option<String>,

    /// Optional explicit subcommand. Omit to run the default scan.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan a directory or file for backend security flows. Identical
    /// to the bare `stryx` invocation; kept for explicit-form scripts.
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, default_value = "human")]
        format: String,
        #[arg(long, default_value = "high")]
        fail_on: String,
        #[arg(long)]
        verbose: bool,
        #[arg(long, value_name = "BASE")]
        diff: Option<String>,
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
        None => cmd_scan(
            &cli.path,
            &cli.format,
            &cli.fail_on,
            cli.verbose,
            cli.diff.as_deref(),
        ),
        Some(Command::Scan {
            path,
            format,
            fail_on,
            verbose,
            diff,
        }) => cmd_scan(&path, &format, &fail_on, verbose, diff.as_deref()),
        Some(Command::Version) => cmd_version(),
        Some(Command::Rules) => cmd_rules(),
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
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
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

fn cmd_scan(
    path: &Path,
    format_str: &str,
    fail_on: &str,
    verbose: bool,
    diff: Option<&str>,
) -> Result<ExitCode> {
    let format = ReportFormat::parse(format_str)
        .with_context(|| format!("unknown --format value: {format_str}"))?;
    let fail_threshold =
        parse_severity(fail_on).with_context(|| format!("unknown --fail-on value: {fail_on}"))?;

    let options = ScanOptions {
        diff_base: diff.map(str::to_string),
    };
    let result = scan_with_options(path, &options)?;

    if result.findings.is_empty() && result.sources.is_empty() {
        eprintln!(
            "stryx: no TypeScript/JavaScript files found at {}",
            path.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    write_report(
        &mut handle,
        &result.findings,
        |p| result.sources.get(p).cloned(),
        Some(&result.profile),
        format,
        ReportOptions {
            verbose,
            file_count: result.file_count,
            elapsed_ms: result.elapsed_ms,
        },
    )?;

    let max_severity = result.findings.iter().map(|f| f.severity).max();
    let should_fail = matches!(max_severity, Some(s) if s >= fail_threshold);
    Ok(if should_fail {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
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
