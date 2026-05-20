//! Reporters consume `Finding`s and turn them into bytes for stdout, files,
//! or CI annotations. JSON output is part of the public CLI contract; human
//! output is best-effort prose for terminal users.

use serde::Serialize;
use std::io::{self, Write};
use stryx_core::{Finding, Severity};
use stryx_index::profile::{
    AuthHint, DataLayerHint, DeploymentHint, FrameworkHint, LanguageHint, LlmSdkHint,
    ProjectProfile, RuntimeHint, ValidatorHint,
};

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
/// a breaking change. `profile` is additive: omitted when no stack
/// evidence is present, so the envelope stays byte-identical for
/// stack-less projects (preserves SemVer for existing consumers).
#[derive(Debug, Serialize)]
pub struct JsonReport<'a> {
    pub schema: &'static str,
    pub findings: &'a [Finding],
    pub summary: ReportSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<&'a ProjectProfile>,
}

#[derive(Debug, Serialize)]
pub struct ReportSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    /// 0–100 health score. 100 means no findings. Per-severity deductions
    /// are then bounded by a per-severity cap so a single Critical can
    /// never look "mostly healthy". Field is additive — placed after the
    /// existing counts so positional JSON readers see counts first.
    pub score: u32,
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
            score: 100,
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
        s.score = compute_score(s.critical, s.high, s.medium, s.low);
        s
    }
}

/// Compute the 0–100 health score from severity counts.
///
/// Deductions apply at the highest-severity tier present (Critical -10,
/// High -5, Medium -2, Low -1, Info 0), clamp at 0, then take the MIN
/// with the lowest applicable severity cap. Cap selection picks the
/// LOWEST applicable cap: one Critical + ten High caps at 49 (Critical),
/// not 74 (High) — so the deduction count for the High findings does
/// not override the stricter Critical ceiling.
fn compute_score(critical: usize, high: usize, medium: usize, low: usize) -> u32 {
    let (per_finding, cap, count): (usize, usize, usize) = if critical > 0 {
        (10, 49, critical)
    } else if high > 0 {
        (5, 74, high)
    } else if medium > 0 {
        (2, 89, medium)
    } else if low > 0 {
        (1, 99, low)
    } else {
        return 100;
    };
    let deduction = per_finding.saturating_mul(count);
    let deducted = 100usize.saturating_sub(deduction);
    deducted.min(cap) as u32
}

/// Controls beyond format selection — verbosity, scan metadata used in
/// the human footer. Kept as a struct (not extra positional args) so
/// future additions (e.g. `--no-summary`, `--no-stack`) don't churn
/// every caller.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReportOptions {
    /// Print every finding rather than the representative-locations
    /// grouping. JSON output is always full and ignores this flag.
    pub verbose: bool,
    /// Number of source files scanned. Shown in the human footer
    /// (`scanned N files in Mms`). Set to 0 to omit.
    pub file_count: usize,
    /// Wall-clock scan duration in milliseconds. Shown in the human
    /// footer. Set to 0 to omit.
    pub elapsed_ms: u128,
}

pub fn write_report<W: Write>(
    out: &mut W,
    findings: &[Finding],
    source_lookup: impl Fn(&std::path::Path) -> Option<String>,
    profile: Option<&ProjectProfile>,
    format: ReportFormat,
    options: ReportOptions,
) -> io::Result<()> {
    match format {
        ReportFormat::Json => write_json(out, findings, profile),
        ReportFormat::Human => write_human(out, findings, source_lookup, profile, options),
    }
}

fn write_json<W: Write>(
    out: &mut W,
    findings: &[Finding],
    profile: Option<&ProjectProfile>,
) -> io::Result<()> {
    let profile = profile.filter(|p| !p.is_empty());
    let report = JsonReport {
        schema: "stryx.findings/v1",
        findings,
        summary: ReportSummary::from_findings(findings),
        profile,
    };
    serde_json::to_writer_pretty(&mut *out, &report)?;
    out.write_all(b"\n")
}

fn write_human<W: Write>(
    out: &mut W,
    findings: &[Finding],
    source_lookup: impl Fn(&std::path::Path) -> Option<String>,
    profile: Option<&ProjectProfile>,
    options: ReportOptions,
) -> io::Result<()> {
    if let Some(profile) = profile
        && !profile.is_empty()
    {
        write_profile_block(out, profile)?;
    }
    if findings.is_empty() {
        writeln!(out, "stryx: no findings")?;
        write_footer(out, options)?;
        return Ok(());
    }
    if options.verbose {
        write_human_findings_full(out, findings, &source_lookup)?;
    } else {
        write_human_findings_grouped(out, findings, &source_lookup)?;
    }
    let summary = ReportSummary::from_findings(findings);
    writeln!(
        out,
        "\n{} finding(s): {} critical, {} high, {} medium, {} low, {} info (score: {}/100)",
        summary.total,
        summary.critical,
        summary.high,
        summary.medium,
        summary.low,
        summary.info,
        summary.score,
    )?;
    write_footer(out, options)?;
    Ok(())
}

/// Verbose output: one block per finding, exactly the pre-grouping
/// shape. Preserved for users piping into grep / regex tools that
/// expect a stable per-finding line shape.
fn write_human_findings_full<W: Write>(
    out: &mut W,
    findings: &[Finding],
    source_lookup: &impl Fn(&std::path::Path) -> Option<String>,
) -> io::Result<()> {
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
    Ok(())
}

/// Default output: groups findings by (severity, rule_id) and shows
/// at most `MAX_REPRESENTATIVES` locations per group with a "+N more"
/// footer when truncated. Same rule-id × same severity is almost
/// always the same fix, so dumping every line of the same group
/// drowns out the higher-priority groups below it. `--verbose`
/// recovers the full list.
fn write_human_findings_grouped<W: Write>(
    out: &mut W,
    findings: &[Finding],
    source_lookup: &impl Fn(&std::path::Path) -> Option<String>,
) -> io::Result<()> {
    const MAX_REPRESENTATIVES: usize = 3;

    // (severity, rule_id) → ordered list of finding indices. BTreeMap
    // gives deterministic iteration; severity is sorted descending
    // because we want Critical first, but Severity's natural Ord is
    // Info → Critical (Info = 0, Critical = 4 in stryx_core). Reverse
    // by storing as `std::cmp::Reverse<Severity>` keys.
    use std::cmp::Reverse;
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<(Reverse<Severity>, &str), Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        groups
            .entry((Reverse(f.severity), f.rule_id.as_ref()))
            .or_default()
            .push(f);
    }
    // Within a group, sort by file path then byte offset so the
    // representative locations are stable across runs.
    for items in groups.values_mut() {
        items.sort_by(|a, b| {
            a.span
                .file
                .cmp(&b.span.file)
                .then(a.span.start.cmp(&b.span.start))
        });
    }

    for ((Reverse(sev), rule), items) in &groups {
        let count = items.len();
        let header = if count == 1 {
            format!("{sev:<8} {rule}  (1 finding)")
        } else {
            format!("{sev:<8} {rule}  ({count} findings)")
        };
        writeln!(out, "{header}")?;
        for f in items.iter().take(MAX_REPRESENTATIVES) {
            let (line, col) = source_lookup(&f.span.file)
                .as_deref()
                .map(|src| line_col(src, f.span.start as usize))
                .unwrap_or((1, 1));
            writeln!(
                out,
                "         {file}:{line}:{col}  {msg}",
                file = f.span.file.display(),
                line = line,
                col = col,
                msg = f.message,
            )?;
        }
        if count > MAX_REPRESENTATIVES {
            writeln!(
                out,
                "         + {} more (run with --verbose for the full list)",
                count - MAX_REPRESENTATIVES
            )?;
        }
        // Help text is uniform per rule id, so print it once at the
        // group level rather than after every representative line.
        if let Some(help) = items.first().and_then(|f| f.help.as_deref()) {
            writeln!(out, "         help: {help}")?;
        }
    }
    Ok(())
}

fn write_footer<W: Write>(out: &mut W, options: ReportOptions) -> io::Result<()> {
    if options.file_count == 0 && options.elapsed_ms == 0 {
        return Ok(());
    }
    let files = if options.file_count == 1 {
        "1 file".to_string()
    } else {
        format!("{} files", options.file_count)
    };
    let elapsed = if options.elapsed_ms < 1000 {
        format!("{}ms", options.elapsed_ms)
    } else {
        format!("{:.2}s", options.elapsed_ms as f64 / 1000.0)
    };
    if options.file_count > 0 && options.elapsed_ms > 0 {
        writeln!(out, "scanned {files} in {elapsed}")
    } else if options.file_count > 0 {
        writeln!(out, "scanned {files}")
    } else {
        writeln!(out, "scan time: {elapsed}")
    }
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

/// Compact profile summary printed at the top of the human report.
/// Only the top-confidence hint per family is shown; full evidence
/// lives in the JSON output.
fn write_profile_block<W: Write>(out: &mut W, profile: &ProjectProfile) -> io::Result<()> {
    let mut parts: Vec<String> = Vec::new();
    let lang = language_label(profile.language);
    if !lang.is_empty() {
        parts.push(format!("language: {lang}"));
    }
    if let Some(d) = profile.runtimes.first() {
        parts.push(format!("runtime: {}", runtime_label(d.id)));
    }
    if let Some(d) = profile.frameworks.first() {
        parts.push(format!("framework: {}", framework_label(d.id)));
    }
    if let Some(d) = profile.data_layers.first() {
        parts.push(format!("data: {}", data_layer_label(d.id)));
    }
    if let Some(d) = profile.validators.first() {
        parts.push(format!("validation: {}", validator_label(d.id)));
    }
    if let Some(d) = profile.auth_layers.first() {
        parts.push(format!("auth: {}", auth_label(d.id)));
    }
    if let Some(d) = profile.llm_sdks.first() {
        parts.push(format!("llm: {}", llm_label(d.id)));
    }
    if let Some(d) = profile.deployments.first() {
        parts.push(format!("deploy: {}", deployment_label(d.id)));
    }
    if parts.is_empty() {
        return Ok(());
    }
    writeln!(out, "stack: {}", parts.join(" • "))?;
    writeln!(out)
}

fn language_label(l: LanguageHint) -> &'static str {
    match l {
        LanguageHint::Unknown => "",
        LanguageHint::JavaScript => "javascript",
        LanguageHint::TypeScript => "typescript",
        LanguageHint::Mixed => "mixed",
    }
}

fn runtime_label(r: RuntimeHint) -> &'static str {
    match r {
        RuntimeHint::Node => "node",
        RuntimeHint::Bun => "bun",
        RuntimeHint::Deno => "deno",
        RuntimeHint::CloudflareWorkers => "cloudflare-workers",
        RuntimeHint::VercelEdge => "vercel-edge",
    }
}

fn framework_label(f: FrameworkHint) -> &'static str {
    match f {
        FrameworkHint::NextBackend => "next",
        FrameworkHint::Hono => "hono",
        FrameworkHint::Express => "express",
        FrameworkHint::Fastify => "fastify",
        FrameworkHint::NestJs => "nestjs",
        FrameworkHint::Elysia => "elysia",
        FrameworkHint::Oak => "oak",
    }
}

fn data_layer_label(d: DataLayerHint) -> &'static str {
    match d {
        DataLayerHint::Prisma => "prisma",
        DataLayerHint::Drizzle => "drizzle",
        DataLayerHint::Kysely => "kysely",
        DataLayerHint::Knex => "knex",
        DataLayerHint::Pg => "pg",
        DataLayerHint::Mysql2 => "mysql2",
        DataLayerHint::BunSqlite => "bun-sqlite",
        DataLayerHint::BunSql => "bun-sql",
        DataLayerHint::Mongoose => "mongoose",
    }
}

fn validator_label(v: ValidatorHint) -> &'static str {
    match v {
        ValidatorHint::Zod => "zod",
        ValidatorHint::Valibot => "valibot",
        ValidatorHint::Yup => "yup",
        ValidatorHint::Joi => "joi",
        ValidatorHint::Ajv => "ajv",
        ValidatorHint::ArkType => "arktype",
        ValidatorHint::TypeBox => "typebox",
        ValidatorHint::ClassValidator => "class-validator",
    }
}

fn auth_label(a: AuthHint) -> &'static str {
    match a {
        AuthHint::BetterAuth => "better-auth",
        AuthHint::AuthJs => "auth.js",
        AuthHint::Clerk => "clerk",
        AuthHint::SupabaseAuth => "supabase-auth",
        AuthHint::Lucia => "lucia",
    }
}

fn llm_label(l: LlmSdkHint) -> &'static str {
    match l {
        LlmSdkHint::OpenAi => "openai",
        LlmSdkHint::Anthropic => "anthropic",
        LlmSdkHint::VercelAiSdk => "vercel-ai-sdk",
        LlmSdkHint::LangChain => "langchain",
    }
}

fn deployment_label(d: DeploymentHint) -> &'static str {
    match d {
        DeploymentHint::Vercel => "vercel",
        DeploymentHint::Cloudflare => "cloudflare",
        DeploymentHint::AwsLambda => "aws-lambda",
        DeploymentHint::Netlify => "netlify",
        DeploymentHint::FlyIo => "fly.io",
        DeploymentHint::Docker => "docker",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stryx_core::Span;

    fn mk(severity: Severity) -> Finding {
        Finding {
            rule_id: "test/rule".to_string(),
            severity,
            message: "test".to_string(),
            span: Span::new(std::path::PathBuf::from("t.ts"), 0, 1),
            source: stryx_core::FindingSource::Ast,
            confidence: stryx_core::Confidence::CERTAIN,
            help: None,
        }
    }

    fn repeat(severity: Severity, n: usize) -> Vec<Finding> {
        (0..n).map(|_| mk(severity)).collect()
    }

    #[test]
    fn score_is_100_when_no_findings() {
        let s = ReportSummary::from_findings(&[]);
        assert_eq!(s.score, 100);
    }

    #[test]
    fn score_one_low_is_99() {
        let s = ReportSummary::from_findings(&repeat(Severity::Low, 1));
        assert_eq!(s.score, 99);
    }

    #[test]
    fn score_one_medium_is_89_cap() {
        // Deduct -2 ⇒ 98, but Medium cap ⇒ min(98, 89) = 89.
        let s = ReportSummary::from_findings(&repeat(Severity::Medium, 1));
        assert_eq!(s.score, 89);
    }

    #[test]
    fn score_one_high_is_74_cap() {
        // Deduct -5 ⇒ 95, but High cap ⇒ min(95, 74) = 74.
        let s = ReportSummary::from_findings(&repeat(Severity::High, 1));
        assert_eq!(s.score, 74);
    }

    #[test]
    fn score_one_critical_is_49_cap() {
        // Deduct -10 ⇒ 90, but Critical cap ⇒ min(90, 49) = 49.
        let s = ReportSummary::from_findings(&repeat(Severity::Critical, 1));
        assert_eq!(s.score, 49);
    }

    #[test]
    fn score_critical_cap_wins_over_high_cap() {
        // Cap-selection picks the LOWEST applicable cap: Critical (49),
        // not High (74). Deductions tier on the highest severity, so
        // only the 1 Critical's -10 counts ⇒ 90, then min(90, 49) = 49.
        // The presence of the 10 High findings does not relax the cap.
        let mut findings = repeat(Severity::Critical, 1);
        findings.extend(repeat(Severity::High, 10));
        let s = ReportSummary::from_findings(&findings);
        assert_eq!(s.score, 49);
    }

    #[test]
    fn score_clamps_at_zero_for_many_lows() {
        // 200 Low ⇒ -200 ⇒ saturate at 0, then Low cap is 99 so
        // min(0, 99) = 0. Must not underflow.
        let s = ReportSummary::from_findings(&repeat(Severity::Low, 200));
        assert_eq!(s.score, 0);
    }

    fn mk_at(rule: &str, severity: Severity, file: &str, start: u32, msg: &str) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            severity,
            message: msg.to_string(),
            span: Span::new(std::path::PathBuf::from(file), start, start + 1),
            source: stryx_core::FindingSource::Ast,
            confidence: stryx_core::Confidence::CERTAIN,
            help: Some("fix it".to_string()),
        }
    }

    fn render(findings: &[Finding], verbose: bool) -> String {
        let mut buf = Vec::new();
        write_human(
            &mut buf,
            findings,
            |_| None,
            None,
            ReportOptions {
                verbose,
                ..Default::default()
            },
        )
        .expect("render");
        String::from_utf8(buf).expect("utf8")
    }

    #[test]
    fn grouped_output_truncates_to_three_representatives() {
        let findings: Vec<Finding> = (0..5)
            .map(|i| {
                mk_at(
                    "flow/x",
                    Severity::High,
                    &format!("file{i}.ts"),
                    i * 10,
                    "hit",
                )
            })
            .collect();
        let out = render(&findings, false);
        assert!(out.contains("flow/x  (5 findings)"), "{out}");
        assert!(out.contains("file0.ts"), "{out}");
        assert!(out.contains("file1.ts"), "{out}");
        assert!(out.contains("file2.ts"), "{out}");
        // file3 and file4 are the truncated tail and must not appear
        // as representative locations.
        assert!(!out.contains("file3.ts"), "{out}");
        assert!(!out.contains("file4.ts"), "{out}");
        assert!(out.contains("+ 2 more"), "{out}");
        // Help is shown once per group, not once per finding.
        assert_eq!(out.matches("help: fix it").count(), 1, "{out}");
    }

    #[test]
    fn grouped_output_sorts_severity_descending_then_rule_id() {
        // Use distinct rule ids so we can match unambiguous header
        // prefixes — searching for bare "low" would hit the "low" in
        // "flow/..." in earlier headers.
        let findings = vec![
            mk_at("rule/b", Severity::Low, "a.ts", 0, "x"),
            mk_at("rule/a", Severity::Critical, "a.ts", 0, "x"),
            mk_at("rule/a", Severity::High, "a.ts", 0, "x"),
        ];
        let out = render(&findings, false);
        // Severity's Display impl bypasses width formatting, so the
        // headers are unpadded: "critical rule/a", "high rule/a",
        // "low rule/b".
        let crit = out.find("critical rule/a").expect("critical header");
        let high = out.find("high rule/a").expect("high header");
        let low = out.find("low rule/b").expect("low header");
        assert!(crit < high && high < low, "{out}");
    }

    #[test]
    fn verbose_output_prints_each_finding_individually() {
        let findings: Vec<Finding> = (0..5)
            .map(|i| {
                mk_at(
                    "flow/x",
                    Severity::High,
                    &format!("file{i}.ts"),
                    i * 10,
                    "hit",
                )
            })
            .collect();
        let out = render(&findings, true);
        // All five files must appear in verbose mode.
        for i in 0..5 {
            assert!(
                out.contains(&format!("file{i}.ts")),
                "missing file{i}: {out}"
            );
        }
        assert!(!out.contains("+ "), "verbose must not show truncation");
        // In verbose mode help repeats per finding (5 times).
        assert_eq!(out.matches("help: fix it").count(), 5, "{out}");
    }
}
