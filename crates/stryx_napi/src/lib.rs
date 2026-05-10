//! Node.js bindings for the Stryx engine via napi-rs.
//!
//! Exposes a single function — [`scan`] — that takes a path and
//! returns the engine's findings as a JSON-serializable structure.
//! All scan logic lives in `stryx_cli::scan` (see
//! `crates/stryx_cli/src/lib.rs`); this crate is just the FFI shim.

#![deny(clippy::all)]

use std::path::PathBuf;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use stryx_core::{Finding, Severity};

/// Findings produced by a scan, plus a count for fast no-prose
/// branching on the JS side.
#[napi(object)]
pub struct ScanReport {
    pub findings: Vec<JsFinding>,
    pub total: u32,
}

/// JS-friendly mirror of `stryx_core::Finding`. Spans are flattened
/// to `(file, start, end)` so consumers don't need the Rust `Span`
/// shape; severity becomes a lowercase string.
#[napi(object)]
pub struct JsFinding {
    pub rule_id: String,
    pub severity: String,
    pub message: String,
    pub help: Option<String>,
    pub file: String,
    pub start: u32,
    pub end: u32,
}

impl From<Finding> for JsFinding {
    fn from(f: Finding) -> Self {
        JsFinding {
            rule_id: f.rule_id.to_string(),
            severity: severity_to_string(f.severity).to_string(),
            message: f.message,
            help: f.help,
            file: f.span.file.to_string_lossy().into_owned(),
            start: f.span.start,
            end: f.span.end,
        }
    }
}

fn severity_to_string(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Scan a path. The returned `findings` array is the merged set
/// across the file tree.
#[napi]
pub fn scan(path: String) -> Result<ScanReport> {
    let result =
        stryx_cli::scan(&PathBuf::from(path)).map_err(|e| Error::from_reason(format!("{e:#}")))?;
    let findings: Vec<JsFinding> = result.findings.into_iter().map(JsFinding::from).collect();
    let total = findings.len() as u32;
    Ok(ScanReport { findings, total })
}
