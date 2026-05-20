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
    profile: Option<&ProjectProfile>,
    format: ReportFormat,
) -> io::Result<()> {
    match format {
        ReportFormat::Json => write_json(out, findings, profile),
        ReportFormat::Human => write_human(out, findings, source_lookup, profile),
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
) -> io::Result<()> {
    if let Some(profile) = profile
        && !profile.is_empty()
    {
        write_profile_block(out, profile)?;
    }
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
