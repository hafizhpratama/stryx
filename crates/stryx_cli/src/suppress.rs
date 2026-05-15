//! Suppression-comment filter for findings.
//!
//! Runs after every rule has produced its findings and drops the ones
//! suppressed by `// stryx-disable-next-line <rule-id>` (line-level)
//! or `// stryx-disable <rule-id>` (file-level) comments.
//!
//! Why centralized: keeping suppression out of every rule's visitor
//! lets the rule code stay ignorant of UX concerns (comment shapes,
//! multi-line tolerance) and means future suppression variants
//! (e.g. per-severity, regex match) extend in one place.
//!
//! Marker syntax recognised:
//!   - `// stryx-disable-next-line <rule-id>[, <rule-id>...]` —
//!     suppresses findings on the immediately-following line
//!   - `// stryx-disable <rule-id>[, <rule-id>...]` — file-wide
//!     suppression for the rules listed
//!   - Both shapes also recognised inside block comments
//!     (`/* … */`) and JSX-style comments (`{/* … */}`)
//!   - `-- <reason>` trailing prose is ignored (it's for human
//!     readers; the comment is valid with or without it)
//!
//! Rule IDs without a slash (e.g. `unvalidated-body-to-db`) are NOT
//! recognised — only fully-qualified IDs like
//! `flow/unvalidated-body-to-db`. This avoids the common typo where
//! a user writes the short name and silently fails to suppress.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use stryx_core::Finding;

/// Filter out findings suppressed by `// stryx-disable*` comments in
/// the source file(s).
pub fn filter_suppressed(
    findings: Vec<Finding>,
    sources: &HashMap<PathBuf, String>,
) -> Vec<Finding> {
    // Parse every source file once into its FileSuppressions. Empty
    // files (no markers) still allocate a default struct, but the
    // lookup is O(1) and the parsing cost is bounded by source size.
    let suppressions: HashMap<&PathBuf, FileSuppressions> = sources
        .iter()
        .map(|(path, content)| (path, FileSuppressions::parse(content)))
        .collect();

    findings
        .into_iter()
        .filter(|f| {
            let Some(supps) = suppressions.get(&f.span.file) else {
                return true;
            };
            let Some(source) = sources.get(&f.span.file) else {
                return true;
            };
            let line = line_for_byte(source, f.span.start);
            !supps.suppresses(&f.rule_id, line)
        })
        .collect()
}

/// Parsed suppression markers for a single source file.
#[derive(Debug, Default)]
struct FileSuppressions {
    /// Rule IDs suppressed everywhere in this file.
    file_level: HashSet<String>,
    /// `line_number → rule IDs suppressed on that line`. The line
    /// number is the *target* line (i.e. the line immediately
    /// following a `stryx-disable-next-line` marker).
    line_level: HashMap<u32, HashSet<String>>,
}

impl FileSuppressions {
    fn parse(content: &str) -> Self {
        let mut out = Self::default();
        for (idx, line) in content.lines().enumerate() {
            // 1-indexed for human-readable line numbers and to match
            // every reporter's convention.
            let line_num = (idx as u32) + 1;
            for marker in extract_markers(line) {
                match marker.kind {
                    MarkerKind::DisableNextLine => {
                        out.line_level
                            .entry(line_num + 1)
                            .or_default()
                            .extend(marker.rule_ids);
                    }
                    MarkerKind::DisableFile => {
                        out.file_level.extend(marker.rule_ids);
                    }
                }
            }
        }
        out
    }

    fn suppresses(&self, rule_id: &str, line: u32) -> bool {
        if self.file_level.contains(rule_id) {
            return true;
        }
        self.line_level
            .get(&line)
            .is_some_and(|r| r.contains(rule_id))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkerKind {
    DisableNextLine,
    DisableFile,
}

#[derive(Debug)]
struct Marker {
    kind: MarkerKind,
    rule_ids: Vec<String>,
}

/// Find every suppression marker on a single source line. Returns
/// empty when none. Recognised contexts:
///   `// stryx-disable-next-line ...`
///   `/* stryx-disable-next-line ... */`
///   `{/* stryx-disable-next-line ... */}` (JSX shape)
/// All three reduce to: the substring `stryx-disable-next-line` or
/// `stryx-disable` appears, preceded somewhere on the line by a
/// `//` or `/*` opener.
fn extract_markers(line: &str) -> Vec<Marker> {
    let mut out = Vec::new();
    // Hot-path early-out: most lines don't contain the marker text.
    if !line.contains("stryx-disable") {
        return out;
    }
    // Try each comment-opener prefix in turn. Order matters: check
    // `stryx-disable-next-line` first because it shares a prefix
    // with `stryx-disable`. A `//` line containing the longer form
    // would otherwise match the shorter form's rest as
    // ` -next-line` which doesn't parse cleanly.
    for &(opener, _close) in &[("//", ""), ("/*", "*/"), ("{/*", "*/}")] {
        let Some(open_idx) = line.find(opener) else {
            continue;
        };
        let after_open = &line[open_idx + opener.len()..];
        let trimmed = after_open.trim_start();
        if let Some(rest) = trimmed.strip_prefix("stryx-disable-next-line") {
            out.push(Marker {
                kind: MarkerKind::DisableNextLine,
                rule_ids: parse_rule_ids(rest),
            });
        } else if let Some(rest) = trimmed.strip_prefix("stryx-disable") {
            out.push(Marker {
                kind: MarkerKind::DisableFile,
                rule_ids: parse_rule_ids(rest),
            });
        }
    }
    out
}

/// Parse the comma- or whitespace-separated rule-ID list that follows
/// the marker keyword, dropping anything after `--` (the reason).
fn parse_rule_ids(rest: &str) -> Vec<String> {
    // Strip the closing `*/` (or `*/}`) if present — we matched the
    // marker keyword but the rest of the line may still contain a
    // block-comment close that's not part of the rule-id list.
    let cleaned = rest
        .split("*/")
        .next()
        .unwrap_or(rest)
        // Trailing `--` introduces human-readable prose; drop it.
        .split("--")
        .next()
        .unwrap_or("");
    cleaned
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
        // Only accept fully-qualified IDs (containing `/`). This
        // catches the common typo where a user writes the short
        // name (`unvalidated-body-to-db`) instead of the full ID
        // (`flow/unvalidated-body-to-db`); silently accepting the
        // short name would let the suppression appear to work but
        // actually do nothing.
        .filter(|s| s.contains('/'))
        .map(String::from)
        .collect()
}

/// 1-indexed line number for a byte offset into a UTF-8 string.
/// Matches the line-numbering convention used by every reporter.
fn line_for_byte(source: &str, byte_offset: u32) -> u32 {
    let target = byte_offset as usize;
    let mut line = 1u32;
    let mut pos = 0usize;
    for ch in source.chars() {
        if pos >= target {
            break;
        }
        if ch == '\n' {
            line += 1;
        }
        pos += ch.len_utf8();
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use stryx_core::{Finding, Severity, Span};

    fn make_finding(file: &str, rule_id: &str, byte_offset: u32) -> Finding {
        Finding::ast(
            // SAFETY: cast to &'static str is fine for tests because
            // these literals live for the whole process.
            Box::leak(rule_id.to_string().into_boxed_str()),
            Severity::High,
            "test",
            Span::new(PathBuf::from(file), byte_offset, byte_offset + 1),
        )
    }

    fn sources(file: &str, content: &str) -> HashMap<PathBuf, String> {
        let mut m = HashMap::new();
        m.insert(PathBuf::from(file), content.to_string());
        m
    }

    #[test]
    fn empty_file_drops_nothing() {
        let f = make_finding("/x.ts", "flow/sql-injection", 0);
        let s = sources("/x.ts", "code\n");
        assert_eq!(filter_suppressed(vec![f], &s).len(), 1);
    }

    #[test]
    fn disable_next_line_with_matching_rule_drops_finding() {
        let content = "// stryx-disable-next-line flow/sql-injection\ndangerous(body)\n";
        let s = sources("/x.ts", content);
        let f = make_finding(
            "/x.ts",
            "flow/sql-injection",
            "// stryx-disable-next-line flow/sql-injection\n".len() as u32,
        );
        assert_eq!(filter_suppressed(vec![f], &s).len(), 0);
    }

    #[test]
    fn disable_next_line_with_non_matching_rule_keeps_finding() {
        let content = "// stryx-disable-next-line flow/redirect-open\ndangerous(body)\n";
        let s = sources("/x.ts", content);
        let f = make_finding(
            "/x.ts",
            "flow/sql-injection",
            "// stryx-disable-next-line flow/redirect-open\n".len() as u32,
        );
        assert_eq!(filter_suppressed(vec![f], &s).len(), 1);
    }

    #[test]
    fn disable_file_level_drops_all_matching() {
        let content = "// stryx-disable flow/sql-injection\nfirst()\nsecond()\n";
        let s = sources("/x.ts", content);
        let line2_byte = content.find("first").unwrap() as u32;
        let line3_byte = content.find("second").unwrap() as u32;
        let f1 = make_finding("/x.ts", "flow/sql-injection", line2_byte);
        let f2 = make_finding("/x.ts", "flow/sql-injection", line3_byte);
        assert_eq!(filter_suppressed(vec![f1, f2], &s).len(), 0);
    }

    #[test]
    fn multiple_rule_ids_on_one_marker() {
        let content =
            "// stryx-disable-next-line flow/sql-injection, flow/redirect-open\ndangerous()\n";
        let s = sources("/x.ts", content);
        let line2_byte = content.find("dangerous").unwrap() as u32;
        let f1 = make_finding("/x.ts", "flow/sql-injection", line2_byte);
        let f2 = make_finding("/x.ts", "flow/redirect-open", line2_byte);
        let f3 = make_finding("/x.ts", "flow/path-traversal", line2_byte);
        let out = filter_suppressed(vec![f1, f2, f3], &s);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "flow/path-traversal");
    }

    #[test]
    fn reason_after_dashes_is_ignored() {
        let content =
            "// stryx-disable-next-line flow/sql-injection -- signed webhook input\nfoo()\n";
        let s = sources("/x.ts", content);
        let line2_byte = content.find("foo").unwrap() as u32;
        let f = make_finding("/x.ts", "flow/sql-injection", line2_byte);
        assert_eq!(filter_suppressed(vec![f], &s).len(), 0);
    }

    #[test]
    fn block_comment_marker_works() {
        let content = "/* stryx-disable-next-line flow/sql-injection */\nfoo()\n";
        let s = sources("/x.ts", content);
        let line2_byte = content.find("foo").unwrap() as u32;
        let f = make_finding("/x.ts", "flow/sql-injection", line2_byte);
        assert_eq!(filter_suppressed(vec![f], &s).len(), 0);
    }

    #[test]
    fn jsx_comment_marker_works() {
        let content =
            "{/* stryx-disable-next-line flow/xss-via-dangerously-set-inner-html */}\n<div />\n";
        let s = sources("/x.tsx", content);
        let line2_byte = content.find("<div").unwrap() as u32;
        let f = make_finding(
            "/x.tsx",
            "flow/xss-via-dangerously-set-inner-html",
            line2_byte,
        );
        assert_eq!(filter_suppressed(vec![f], &s).len(), 0);
    }

    #[test]
    fn unqualified_rule_id_does_not_suppress() {
        // Defends against the typo `sql-injection` (missing `flow/`).
        let content = "// stryx-disable-next-line sql-injection\nfoo()\n";
        let s = sources("/x.ts", content);
        let line2_byte = content.find("foo").unwrap() as u32;
        let f = make_finding("/x.ts", "flow/sql-injection", line2_byte);
        assert_eq!(filter_suppressed(vec![f], &s).len(), 1);
    }

    #[test]
    fn finding_in_unread_file_passes_through() {
        // Defends against the case where the suppression scanner is
        // missing a source file the finding references (shouldn't
        // happen in practice — scan() reads every parsed file —
        // but ensures we fail-open rather than fail-closed).
        let f = make_finding("/unread.ts", "flow/sql-injection", 0);
        let s = sources("/other.ts", "// stryx-disable flow/sql-injection\n");
        assert_eq!(filter_suppressed(vec![f], &s).len(), 1);
    }

    #[test]
    fn line_for_byte_handles_multibyte_chars() {
        let s = "// 日本語コメント\nfoo()\n";
        let byte_of_foo = s.find("foo").unwrap() as u32;
        assert_eq!(line_for_byte(s, byte_of_foo), 2);
    }
}
