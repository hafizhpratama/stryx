use crate::{Rule, RuleContext, RuleMeta};
use regex::Regex;
use std::path::PathBuf;
use stryx_ast::{
    Visit,
    ast::{
        BindingPattern, Expression, ObjectProperty, PropertyKey, StringLiteral, VariableDeclarator,
    },
    to_span,
};
use stryx_core::{Finding, Severity};

const RULE_ID: &str = "generic/hardcoded-secret";

/// `generic/hardcoded-secret` — flags credential-shaped string literals.
///
/// Two detection modes:
///
/// - **Provider-prefix (Critical)**: well-known token shapes for AWS,
///   Anthropic, Stripe, GitHub, OpenAI. Conservative — only matches
///   high-confidence prefixes. Fires anywhere the string literal
///   appears.
///
/// - **Credential-named binding (High)**: a string literal of
///   plausible-secret shape (length ≥ 16, alphanumeric, not a
///   recognisable placeholder) assigned to a binding or object
///   property whose NAME suggests it's a secret (`apiKey`, `secret`,
///   `accessToken`, `STRIPE_KEY`, ...). The name-based mode catches
///   the NodeGoat-shaped `zapApiKey: "v9dn0balpqas1pcc281tn5ood1"`
///   case where no known prefix would match. Higher FP risk than the
///   provider-prefix mode, so emitted at High rather than Critical.
pub struct HardcodedSecret {
    patterns: Vec<(Severity, Regex, &'static str)>,
    credential_name_re: Regex,
    placeholder_patterns: Vec<Regex>,
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
        // Same credential-name shape as flow/secret-to-response uses for
        // its destructured-binding detection — kept in lockstep so a
        // value flagged at the source by this rule and at the response
        // boundary by the other rule speaks the same vocabulary.
        //
        // The pattern requires that the credential keyword be followed
        // by an end-of-string anchor or a non-letter — this lets it
        // match `apiKey`, `API_KEY`, `accessToken` while *rejecting*
        // metadata-shaped names like `tokenNamePrefix`, `keyPath`,
        // `secretType`, `passwordHasher`. A name like `tokenName` is
        // a name FOR a token, not the token itself; same for `*Prefix`,
        // `*Suffix`, `*Type`, `*Path`, `*Length`, `*Hasher`, `*Field`.
        // Without this distinction the rule produced 30+ FPs on the
        // documenso test suite's `tokenNamePrefix: "e2e-..."` lines.
        let credential_name_re = Regex::new(
            r"(?i)(SECRET|KEY|TOKEN|PASSWORD|PASSWD|JWT|PRIVATE|CREDENTIAL|DSN)(?:[^A-Za-z]|$)",
        )
        .expect("static regex compiles");
        // Strings that LOOK secret-shaped but are obviously placeholder
        // values someone left in source as a hint for env config. False
        // positives here drown out the real signal — anything matching
        // is silently skipped by the credential-name heuristic.
        let placeholder_patterns = [
            r"(?i)^(your|my|some)[-_ ]?(api[-_ ]?key|secret|token|password|pass)",
            r"(?i)^example",
            r"(?i)^placeholder",
            r"(?i)^changeme",
            r"(?i)^todo",
            r"(?i)^test[-_]?(api[-_]?key|secret|token|password)",
            r"^(undefined|null|true|false)$",
            r"^(x{3,}|\*{3,}|\.{3,}|-{3,})$",
            // Anything that LOOKS like a URL is almost certainly a
            // config value, not a credential.
            r"^https?://",
            r"^\$\{",   // template placeholder `${SECRET}`
            r"^<[A-Z]", // `<YOUR_KEY>` style
        ]
        .into_iter()
        .map(|p| Regex::new(p).expect("static regex compiles"))
        .collect();
        Self {
            patterns,
            credential_name_re,
            placeholder_patterns,
        }
    }

    /// True if `value` plausibly looks like a real secret rather than
    /// a placeholder / dummy / public config value.
    fn looks_like_secret_value(&self, value: &str) -> bool {
        if value.len() < 16 {
            return false;
        }
        if self.placeholder_patterns.iter().any(|p| p.is_match(value)) {
            return false;
        }
        // Require at least one digit AND one letter — pure-letter
        // strings (`"thisisaverylongname"`) are almost never secrets;
        // pure-digit strings (`"1234567890123456"`) are usually IDs.
        let has_digit = value.bytes().any(|b| b.is_ascii_digit());
        let has_alpha = value.bytes().any(|b| b.is_ascii_alphabetic());
        has_digit && has_alpha
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
            description: "Detects credential-shaped string literals (AWS, Anthropic, Stripe, GitHub, OpenAI) and credential-named bindings with plausible-secret values.",
        }
    }

    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding> {
        let mut visitor = SecretVisitor {
            findings: Vec::new(),
            file: ctx.file.path.clone(),
            rule: self,
        };
        visitor.visit_program(&ctx.file.program);
        visitor.findings
    }
}

struct SecretVisitor<'a> {
    findings: Vec<Finding>,
    file: PathBuf,
    rule: &'a HardcodedSecret,
}

impl<'a> SecretVisitor<'_> {
    /// Emit a credential-named-binding finding if `value_str` looks
    /// like a real secret. The `name` is the binding/property key
    /// already verified to match `credential_name_re`. Severity is
    /// High because name-shaped detection runs hotter for FPs than
    /// the provider-prefix mode.
    fn emit_named_credential(&mut self, name: &str, value_lit: &StringLiteral<'a>) {
        // Bare generic names match the credential regex but in
        // practice almost always describe non-credential payloads:
        // `key: 'yyyy-MM-dd_HH:mm'` (date-format key in documenso),
        // `token: 'next-page-cursor'`, `secret: 'todo'`. Compound
        // names (`apiKey`, `accessToken`) are far more reliable
        // signals — kept in lockstep with the
        // flow/secret-to-response rule's same exclusion list.
        const TOO_GENERIC_BARE_NAMES: &[&str] = &[
            "key",
            "token",
            "secret",
            "password",
            "passwd",
            "credential",
            "private",
            "jwt",
            "dsn",
        ];
        if TOO_GENERIC_BARE_NAMES
            .iter()
            .any(|n| n.eq_ignore_ascii_case(name))
        {
            return;
        }
        let value = value_lit.value.as_str();
        if !self.rule.looks_like_secret_value(value) {
            return;
        }
        // Don't double-flag: if the literal already matches one of
        // the provider-prefix patterns, the `visit_string_literal`
        // pass emits a Critical finding at the same span. Suppress
        // the credential-named (High) emission to keep one finding
        // per real issue. The Critical message is more actionable
        // anyway — it names the specific provider.
        if self
            .rule
            .patterns
            .iter()
            .any(|(_, re, _)| re.is_match(value))
        {
            return;
        }
        let span = to_span(&self.file, value_lit.span);
        let message = format!(
            "Credential-named binding `{name}` holds a hardcoded secret-shaped string value"
        );
        self.findings.push(
            Finding::ast(RULE_ID, Severity::High, message, span)
                .with_help("Move the value to an environment variable or secret manager; commit only a placeholder (`process.env.X`)."),
        );
    }
}

impl<'a> Visit<'a> for SecretVisitor<'_> {
    fn visit_string_literal(&mut self, lit: &StringLiteral<'a>) {
        let value: &str = lit.value.as_str();
        if value.len() < 16 {
            return;
        }
        for (severity, re, message) in &self.rule.patterns {
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

    fn visit_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
        // `const apiKey = "v9dn0balpqas1pcc281tn5ood1"` — name-on-the-
        // left-of-`=` form. Only single-identifier bindings; destructure
        // patterns are intentionally out of scope here (they're handled
        // by flow/secret-to-response when the destructure goes into a
        // response).
        if let BindingPattern::BindingIdentifier(id) = &decl.id
            && self.rule.credential_name_re.is_match(id.name.as_str())
            && let Some(Expression::StringLiteral(lit)) = &decl.init
        {
            self.emit_named_credential(id.name.as_str(), lit);
        }
        // Recurse so nested patterns still get the string-literal pass.
        if let Some(init) = &decl.init {
            self.visit_expression(init);
        }
    }

    fn visit_object_property(&mut self, prop: &ObjectProperty<'a>) {
        // `apiKey: "v9dn0balpqas1pcc281tn5ood1"` — config-object form.
        // This is the NodeGoat shape: a TS/JS module exporting a config
        // map with credential-named keys.
        if let PropertyKey::StaticIdentifier(name) = &prop.key
            && self.rule.credential_name_re.is_match(name.name.as_str())
            && let Expression::StringLiteral(lit) = &prop.value
        {
            self.emit_named_credential(name.name.as_str(), lit);
        }
        // Recurse so the value side keeps getting the string-literal
        // pass for the provider-prefix detection.
        self.visit_expression(&prop.value);
    }
}
