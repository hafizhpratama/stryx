//! Reporters consume `Finding`s and turn them into bytes for stdout, files,
//! or CI annotations. JSON output is part of the public CLI contract; human
//! output is best-effort prose for terminal users.

use serde::Serialize;
use std::io::{self, Write};
use stryx_core::{Finding, Severity};

/// Output format requested on the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Human,
    Json,
}

impl ReportFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "human" | "text" => Some(Self::Human),
            "json" => Some(Self::Json),
            _ => None,
        }
    }
}

/// JSON envelope. Schema is part of the public CLI contract — bumping it is
/// a breaking change.
#[derive(Debug, Serialize)]
pub struct JsonReport<'a> {
    pub schema: &'static str,
    pub findings: &'a [Finding],
    pub summary: ReportSummary,
}

#[derive(Debug, Serialize)]
pub struct ReportSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl ReportSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut s = Self {
            total: findings.len(),
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };
        for f in findings {
            match f.severity {
                Severity::Critical => s.critical += 1,
                Severity::High => s.high += 1,
                Severity::Medium => s.medium += 1,
                Severity::Low => s.low += 1,
                Severity::Info => s.info += 1,
            }
        }
        s
    }
}

pub fn write_report<W: Write>(
    out: &mut W,
    findings: &[Finding],
    source_lookup: impl Fn(&std::path::Path) -> Option<String>,
    format: ReportFormat,
) -> io::Result<()> {
    match format {
        ReportFormat::Json => write_json(out, findings),
        ReportFormat::Human => write_human(out, findings, source_lookup),
    }
}

fn write_json<W: Write>(out: &mut W, findings: &[Finding]) -> io::Result<()> {
    let report = JsonReport {
        schema: "stryx.findings/v1",
        findings,
        summary: ReportSummary::from_findings(findings),
    };
    serde_json::to_writer_pretty(&mut *out, &report)?;
    out.write_all(b"\n")
}

fn write_human<W: Write>(
    out: &mut W,
    findings: &[Finding],
    source_lookup: impl Fn(&std::path::Path) -> Option<String>,
) -> io::Result<()> {
    if findings.is_empty() {
        return writeln!(out, "stryx: no findings");
    }
    for f in findings {
        let (line, col) = source_lookup(&f.span.file)
            .as_deref()
            .map(|src| line_col(src, f.span.start as usize))
            .unwrap_or((1, 1));
        writeln!(
            out,
            "{sev:<8} {rule}  {file}:{line}:{col}",
            sev = f.severity,
            rule = f.rule_id,
            file = f.span.file.display(),
            line = line,
            col = col,
        )?;
        writeln!(out, "         {}", f.message)?;
        if let Some(help) = &f.help {
            writeln!(out, "         help: {}", help)?;
        }
    }
    let summary = ReportSummary::from_findings(findings);
    writeln!(
        out,
        "\n{} finding(s): {} critical, {} high, {} medium, {} low, {} info",
        summary.total, summary.critical, summary.high, summary.medium, summary.low, summary.info,
    )
}

fn line_col(source: &str, byte_offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut col = 1usize;
    for (i, ch) in source.char_indices() {
        if i >= byte_offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}
