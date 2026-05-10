use crate::{Rule, RuleContext, RuleMeta};
use regex::Regex;
use std::path::PathBuf;
use stryx_ast::{Visit, ast::StringLiteral, to_span};
use stryx_core::{Finding, Severity};

const RULE_ID: &str = "generic/hardcoded-secret";

/// `generic/hardcoded-secret` — flags credential-shaped string literals.
///
/// Conservative by design: only matches well-known provider prefixes
/// (`sk-ant-`, `AKIA…`, `ghp_…`, `sk_live_…`). Generic high-entropy
/// detection lives behind a future opt-in flag because it is noisy.
pub struct HardcodedSecret {
    patterns: Vec<(Severity, Regex, &'static str)>,
}

impl HardcodedSecret {
    pub fn new() -> Self {
        let patterns = vec![
            (
                Severity::Critical,
                Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
                "AWS access key id committed in source",
            ),
            (
                Severity::Critical,
                Regex::new(r"\bsk-ant-[A-Za-z0-9_\-]{20,}").unwrap(),
                "Anthropic API key committed in source",
            ),
            (
                Severity::Critical,
                Regex::new(r"\bsk_(live|test)_[A-Za-z0-9]{20,}\b").unwrap(),
                "Stripe secret key committed in source",
            ),
            (
                Severity::Critical,
                Regex::new(r"\bghp_[A-Za-z0-9]{36}\b").unwrap(),
                "GitHub personal access token committed in source",
            ),
            (
                Severity::High,
                Regex::new(r"^sk-[A-Za-z0-9]{40,}$").unwrap(),
                "OpenAI-shaped API key committed in source",
            ),
        ];
        Self { patterns }
    }
}

impl Default for HardcodedSecret {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for HardcodedSecret {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: RULE_ID,
            default_severity: Severity::Critical,
            description: "Detects credential-shaped string literals (AWS, Anthropic, Stripe, GitHub, OpenAI).",
        }
    }

    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding> {
        let mut visitor = SecretVisitor {
            findings: Vec::new(),
            file: ctx.file.path.clone(),
            patterns: &self.patterns,
        };
        visitor.visit_program(&ctx.file.program);
        visitor.findings
    }
}

struct SecretVisitor<'a> {
    findings: Vec<Finding>,
    file: PathBuf,
    patterns: &'a [(Severity, Regex, &'static str)],
}

impl<'a> Visit<'a> for SecretVisitor<'_> {
    fn visit_string_literal(&mut self, lit: &StringLiteral<'a>) {
        let value: &str = lit.value.as_str();
        if value.len() < 16 {
            return;
        }
        for (severity, re, message) in self.patterns {
            if re.is_match(value) {
                let span = to_span(&self.file, lit.span);
                self.findings.push(
                    Finding::ast(RULE_ID, *severity, (*message).to_string(), span)
                        .with_help("Move secrets to environment variables or a secret manager."),
                );
                break;
            }
        }
    }
}
