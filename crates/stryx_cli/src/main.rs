use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use stryx_cli::scan;
use stryx_core::Severity;
use stryx_reporter::{ReportFormat, write_report};
use stryx_rules::builtin_rules;

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
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into());
    // Logs go to stderr so `--format json` emits a clean JSON document
    // on stdout that downstream tools can pipe into `jq`. The default
    // tracing-subscriber writer is stdout, which is the wrong choice
    // for a CLI that produces machine-readable output.
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

fn cmd_scan(path: &Path, format_str: &str, fail_on: &str) -> Result<ExitCode> {
    let format = ReportFormat::parse(format_str)
        .with_context(|| format!("unknown --format value: {format_str}"))?;
    let fail_threshold =
        parse_severity(fail_on).with_context(|| format!("unknown --fail-on value: {fail_on}"))?;

    let result = scan(path)?;

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
        format,
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
