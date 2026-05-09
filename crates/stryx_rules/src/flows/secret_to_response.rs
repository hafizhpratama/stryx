//! `flow/secret-to-response` — slice 1 (single-file).
//!
//! Detects secret-shaped values flowing into a response-body sink without
//! redaction. v0.0.1 covers the most common real-world failure mode: a
//! debug / health / config endpoint that bundles `process.env` (or
//! hardcoded credentials) directly into the response.
//!
//! Cross-file flow is deferred to slice 2 — same architecture as the
//! `flow/unvalidated-body-to-db` rule will be reused (per-file extract
//! pass + per-function ParamFlow).

use std::collections::HashSet;
use std::path::PathBuf;

use regex::Regex;
use stryx_ast::{
    ast::{
        ArrowFunctionExpression, BindingPattern, CallExpression, Expression, Function,
        MemberExpression, ObjectPropertyKind, Statement, VariableDeclaration,
    },
    to_span, ScopeFlags, Visit,
};
use stryx_core::{Finding, Severity};

use crate::{Rule, RuleContext, RuleMeta};

const RULE_ID: &str = "flow/secret-to-response";

/// Names treated as public-by-convention regardless of suffix. Backed by
/// concrete prefix and exact-name lists so a `stryx.toml` override can
/// extend either dimension without regex surgery.
const PUBLIC_ENV_PREFIXES: &[&str] = &["NEXT_PUBLIC_", "PUBLIC_", "VITE_", "REACT_APP_"];
const PUBLIC_ENV_EXACT: &[&str] = &[
    "NODE_ENV",
    "NEXT_RUNTIME",
    "APP_VERSION",
    "VERCEL",
    "VERCEL_ENV",
    "VERCEL_URL",
    "VERCEL_REGION",
    "PORT",
    "HOSTNAME",
    "HOST",
];

/// Names recognised as redaction sanitisers. Calling `redact(secret)`
/// strips the Secret label even though the call result is still derived
/// from the secret.
const REDACT_FN_NAMES: &[&str] = &["redact", "mask", "fingerprint", "hash"];

pub struct SecretToResponse {
    secret_name_re: Regex,
    credential_patterns: Vec<Regex>,
}

impl SecretToResponse {
    pub fn new() -> Self {
        // Conservative secret-name regex. AUTH and API are deliberately
        // omitted — `AUTH_URL` and `API_URL` are commonly public, while
        // genuinely-secret variants (`NEXTAUTH_SECRET`, `API_KEY`) match
        // SECRET / KEY anyway.
        let secret_name_re =
            Regex::new(r"(?i)SECRET|KEY|TOKEN|PASSWORD|PASSWD|JWT|PRIVATE|CREDENTIAL|DSN")
                .expect("static regex compiles");

        // Same provider-prefixed credential shapes as the
        // generic/hardcoded-secret rule. Reused here so a credential
        // appearing inline at a response sink is doubly flagged: once
        // for being in source (generic rule), once for actually leaking
        // (this rule, with higher signal because the leak is active).
        let credential_patterns = [
            r"\bAKIA[0-9A-Z]{16}\b",
            r"\bsk-ant-[A-Za-z0-9_\-]{20,}",
            r"\bsk_(live|test)_[A-Za-z0-9]{20,}\b",
            r"\bghp_[A-Za-z0-9]{36}\b",
            r"^sk-[A-Za-z0-9]{40,}$",
        ]
        .into_iter()
        .map(|p| Regex::new(p).expect("static regex compiles"))
        .collect();

        Self {
            secret_name_re,
            credential_patterns,
        }
    }
}

impl Default for SecretToResponse {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SecretToResponse {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: RULE_ID,
            default_severity: Severity::Critical,
            description: "Secret-shaped value reaches a response body without redaction.",
        }
    }

    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding> {
        let mut visitor = SecretFlowVisitor::new(ctx.file.path.clone(), self);
        visitor.visit_program(&ctx.file.program);
        visitor.findings
    }
}

struct SecretFlowVisitor<'r> {
    file: PathBuf,
    rule: &'r SecretToResponse,
    findings: Vec<Finding>,
    /// Stack of per-function scopes; each frame holds the names of
    /// identifiers currently carrying the Secret label.
    scopes: Vec<HashSet<String>>,
}

impl<'r> SecretFlowVisitor<'r> {
    fn new(file: PathBuf, rule: &'r SecretToResponse) -> Self {
        Self {
            file,
            rule,
            findings: Vec::new(),
            scopes: Vec::new(),
        }
    }

    fn enter_fn(&mut self) {
        self.scopes.push(HashSet::new());
    }

    fn exit_fn(&mut self) {
        self.scopes.pop();
    }

    fn taint(&mut self, name: String) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name);
        }
    }

    fn is_tainted(&self, name: &str) -> bool {
        self.scopes.iter().rev().any(|s| s.contains(name))
    }

    fn handle_function_body(&mut self, body: &[Statement<'_>]) {
        for stmt in body {
            self.handle_statement(stmt);
        }
    }

    fn handle_statement(&mut self, stmt: &Statement<'_>) {
        match stmt {
            Statement::VariableDeclaration(decl) => self.handle_var_decl(decl),
            Statement::ExpressionStatement(es) => {
                self.scan_for_sinks(&es.expression);
            }
            Statement::ReturnStatement(rs) => {
                if let Some(arg) = &rs.argument {
                    self.scan_for_sinks(arg);
                }
            }
            Statement::BlockStatement(bs) => {
                for s in &bs.body {
                    self.handle_statement(s);
                }
            }
            Statement::IfStatement(is) => {
                self.handle_statement(&is.consequent);
                if let Some(alt) = &is.alternate {
                    self.handle_statement(alt);
                }
            }
            Statement::TryStatement(ts) => {
                for s in &ts.block.body {
                    self.handle_statement(s);
                }
                if let Some(handler) = &ts.handler {
                    for s in &handler.body.body {
                        self.handle_statement(s);
                    }
                }
                if let Some(finalizer) = &ts.finalizer {
                    for s in &finalizer.body {
                        self.handle_statement(s);
                    }
                }
            }
            Statement::WhileStatement(ws) => self.handle_statement(&ws.body),
            Statement::DoWhileStatement(ds) => self.handle_statement(&ds.body),
            Statement::ForStatement(fs) => self.handle_statement(&fs.body),
            Statement::ForOfStatement(fs) => self.handle_statement(&fs.body),
            Statement::ForInStatement(fs) => self.handle_statement(&fs.body),
            Statement::SwitchStatement(ss) => {
                for case in &ss.cases {
                    for s in &case.consequent {
                        self.handle_statement(s);
                    }
                }
            }
            Statement::LabeledStatement(ls) => self.handle_statement(&ls.body),
            other => self.visit_statement(other),
        }
    }

    fn handle_var_decl(&mut self, decl: &VariableDeclaration<'_>) {
        for declarator in &decl.declarations {
            let Some(init) = &declarator.init else {
                continue;
            };
            self.scan_for_sinks(init);
            // Object-destructure: `const { apiKey, ...rest } = config`.
            // Bindings whose key name itself looks secret-shaped inherit
            // taint; the rest binding (if any) is treated as clean — the
            // secret-named keys were peeled off, so `rest` no longer
            // carries them. (Strict mode would require an enumerated
            // destructure of every secret key on the receiver; for
            // v0.0.1 we accept the looser model.)
            if let BindingPattern::ObjectPattern(o) = &declarator.id {
                for prop in &o.properties {
                    let stryx_ast::ast::PropertyKey::StaticIdentifier(id) = &prop.key else {
                        continue;
                    };
                    let BindingPattern::BindingIdentifier(b) = &prop.value else {
                        continue;
                    };
                    if self.rule.secret_name_re.is_match(id.name.as_str()) {
                        self.taint(b.name.to_string());
                    }
                }
                continue;
            }
            // Plain identifier binding.
            if let BindingPattern::BindingIdentifier(id) = &declarator.id
                && self.is_secret_expr(init)
            {
                self.taint(id.name.to_string());
            }
        }
    }

    /// Walks an expression looking for response-body sinks. When a sink
    /// is encountered, scans the argument(s) for Secret taint and emits
    /// findings.
    fn scan_for_sinks(&mut self, expr: &Expression<'_>) {
        match expr {
            Expression::CallExpression(call) => {
                if let Some(sink_label) = response_sink_label(call) {
                    for arg in &call.arguments {
                        let Some(arg_expr) = arg.as_expression() else {
                            continue;
                        };
                        if let Some(reason) = self.secret_reason(arg_expr) {
                            self.findings.push(
                                Finding::ast(
                                    RULE_ID,
                                    Severity::Critical,
                                    format!(
                                        "{reason} reaches `{sink_label}` without redaction.",
                                    ),
                                    to_span(&self.file, call.span),
                                )
                                .with_help(
                                    "Drop the secret field, redact it (e.g. `Boolean(...)`, fingerprint), or move the value to a server-only path that never reaches the client.",
                                ),
                            );
                        }
                    }
                }
                self.scan_for_sinks(&call.callee);
                for arg in &call.arguments {
                    if let Some(e) = arg.as_expression() {
                        self.scan_for_sinks(e);
                    }
                }
            }
            Expression::AwaitExpression(a) => self.scan_for_sinks(&a.argument),
            Expression::ParenthesizedExpression(p) => self.scan_for_sinks(&p.expression),
            Expression::NewExpression(n) => {
                // `new Response(JSON.stringify(secret))` is also a
                // response-body sink. v0.0.1 keeps this narrow: the
                // constructor must be `Response` and the first argument
                // is checked.
                if is_response_constructor(&n.callee)
                    && let Some(first) = n.arguments.first().and_then(|a| a.as_expression())
                    && let Some(reason) = self.secret_reason(first)
                {
                    self.findings.push(
                        Finding::ast(
                            RULE_ID,
                            Severity::Critical,
                            format!("{reason} reaches `new Response(...)` without redaction."),
                            to_span(&self.file, n.span),
                        )
                        .with_help(
                            "Drop the secret field, redact it, or return a sanitised projection.",
                        ),
                    );
                }
                for arg in &n.arguments {
                    if let Some(e) = arg.as_expression() {
                        self.scan_for_sinks(e);
                    }
                }
            }
            _ => {}
        }
    }

    /// Returns a human-readable reason if `expr` carries Secret taint,
    /// or `None` if the expression is clean.
    fn secret_reason(&self, expr: &Expression<'_>) -> Option<String> {
        match expr {
            Expression::Identifier(id) => self
                .is_tainted(id.name.as_str())
                .then(|| format!("secret-shaped value `{}`", id.name)),

            Expression::StringLiteral(s) => self
                .matches_credential_pattern(s.value.as_str())
                .then(|| "hardcoded credential".to_string()),

            Expression::TemplateLiteral(t) => {
                for e in &t.expressions {
                    if let Some(r) = self.secret_reason(e) {
                        return Some(r);
                    }
                }
                None
            }

            Expression::StaticMemberExpression(m) => {
                if let Some(env_name) = process_env_name(expr)
                    && self.is_secret_env_name(&env_name)
                {
                    return Some(format!("`process.env.{env_name}`"));
                }
                self.secret_reason(&m.object)
            }
            Expression::ComputedMemberExpression(m) => self.secret_reason(&m.object),
            Expression::PrivateFieldExpression(m) => self.secret_reason(&m.object),

            Expression::ObjectExpression(obj) => {
                for prop in &obj.properties {
                    match prop {
                        // Shorthand `{ apiKey }` parses as a property
                        // whose value is the same Identifier — the
                        // value branch catches the tainted local.
                        ObjectPropertyKind::ObjectProperty(p) => {
                            if let Some(r) = self.secret_reason(&p.value) {
                                return Some(r);
                            }
                        }
                        ObjectPropertyKind::SpreadProperty(s) => {
                            if let Some(r) = self.secret_reason(&s.argument) {
                                return Some(r);
                            }
                        }
                    }
                }
                None
            }

            Expression::ArrayExpression(arr) => {
                for el in &arr.elements {
                    if let Some(e) = el.as_expression()
                        && let Some(r) = self.secret_reason(e)
                    {
                        return Some(r);
                    }
                }
                None
            }

            Expression::ConditionalExpression(c) => self
                .secret_reason(&c.consequent)
                .or_else(|| self.secret_reason(&c.alternate)),

            Expression::LogicalExpression(b) => self
                .secret_reason(&b.left)
                .or_else(|| self.secret_reason(&b.right)),

            Expression::ParenthesizedExpression(p) => self.secret_reason(&p.expression),
            Expression::AwaitExpression(a) => self.secret_reason(&a.argument),
            Expression::TSAsExpression(t) => self.secret_reason(&t.expression),
            Expression::TSNonNullExpression(t) => self.secret_reason(&t.expression),
            Expression::TSSatisfiesExpression(t) => self.secret_reason(&t.expression),
            Expression::TSTypeAssertion(t) => self.secret_reason(&t.expression),

            Expression::CallExpression(call) => {
                // Sanitisers strip the Secret label.
                if is_redactor_call(call) || is_boolean_coercion(call) {
                    return None;
                }
                // Serialisers (`JSON.stringify(...)`) preserve the
                // contents — the resulting string IS the secret.
                // Recurse into the first argument.
                if is_json_stringify(call)
                    && let Some(first) = call.arguments.first().and_then(|a| a.as_expression())
                {
                    return self.secret_reason(first);
                }
                // Otherwise: opaque call. The "Secret" label does not
                // travel through arbitrary function boundaries — passing
                // a secret as a verification argument doesn't make the
                // returned value secret. Cross-file slice 2 will refine
                // this with per-function summaries; for slice 1 we err
                // on the side of fewer false positives.
                None
            }

            _ => None,
        }
    }

    /// Internal helper used by the var-decl branch to taint a single
    /// initialiser. Mirrors `secret_reason(...).is_some()` but returns
    /// the reason at a higher granularity if needed later.
    fn is_secret_expr(&self, expr: &Expression<'_>) -> bool {
        self.secret_reason(expr).is_some()
    }

    fn is_secret_env_name(&self, name: &str) -> bool {
        if PUBLIC_ENV_EXACT.contains(&name) {
            return false;
        }
        if PUBLIC_ENV_PREFIXES.iter().any(|p| name.starts_with(p)) {
            return false;
        }
        self.rule.secret_name_re.is_match(name)
    }

    fn matches_credential_pattern(&self, value: &str) -> bool {
        if value.len() < 16 {
            return false;
        }
        self.rule
            .credential_patterns
            .iter()
            .any(|re| re.is_match(value))
    }
}

impl<'a> Visit<'a> for SecretFlowVisitor<'_> {
    fn visit_function(&mut self, func: &Function<'a>, _flags: ScopeFlags) {
        self.enter_fn();
        if let Some(body) = &func.body {
            self.handle_function_body(&body.statements);
        }
        self.exit_fn();
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        self.enter_fn();
        self.handle_function_body(&arrow.body.statements);
        self.exit_fn();
    }
}

// ── Source / sink / sanitiser matchers ────────────────────────────────────

/// Returns the env-var name when `expr` is exactly `process.env.X`.
fn process_env_name(expr: &Expression<'_>) -> Option<String> {
    let Expression::StaticMemberExpression(outer) = expr else {
        return None;
    };
    let Expression::StaticMemberExpression(inner) = &outer.object else {
        return None;
    };
    let Expression::Identifier(root) = &inner.object else {
        return None;
    };
    if root.name != "process" || inner.property.name != "env" {
        return None;
    }
    Some(outer.property.name.to_string())
}

/// Returns a label like "Response.json" when `call` is a recognised
/// response-body sink.
fn response_sink_label(call: &CallExpression<'_>) -> Option<String> {
    let MemberExpression::StaticMemberExpression(method) =
        call.callee.as_member_expression()?
    else {
        return None;
    };
    let prop = method.property.name.as_str();
    let receiver = match &method.object {
        Expression::Identifier(id) => id.name.as_str().to_string(),
        // `ctx.json(...)` is fine via Identifier path. But Hono's `c.req`
        // chain isn't a response sink; skip member receivers entirely.
        _ => return None,
    };

    let is_sink = match (receiver.as_str(), prop) {
        // Express / Pages Router style.
        ("res", "json" | "send" | "end" | "write") => true,
        // Fastify.
        ("reply", "send") => true,
        // Hono.
        ("c" | "ctx", "json" | "text" | "html" | "body") => true,
        // Web standard / Next.js App Router static helpers.
        ("Response" | "NextResponse", "json") => true,
        _ => false,
    };
    if !is_sink {
        return None;
    }
    Some(format!("{receiver}.{prop}"))
}

fn is_response_constructor(callee: &Expression<'_>) -> bool {
    matches!(
        callee,
        Expression::Identifier(id) if id.name == "Response"
    )
}

/// Recognises `redact(x)`, `mask(x)`, `fingerprint(x)`, `hash(x)`, or
/// the same names on a member receiver (`utils.redact(x)`,
/// `crypto.hash(x)`).
fn is_redactor_call(call: &CallExpression<'_>) -> bool {
    let name = match &call.callee {
        Expression::Identifier(id) => id.name.as_str(),
        Expression::StaticMemberExpression(m) => m.property.name.as_str(),
        _ => return false,
    };
    REDACT_FN_NAMES.contains(&name)
}

/// `Boolean(secret)` and `!!secret` produce a derived non-secret bool.
/// The double-bang case is handled in the future via UnaryExpression
/// recognition; for v0.0.1 only the explicit constructor call is
/// recognised.
fn is_boolean_coercion(call: &CallExpression<'_>) -> bool {
    matches!(
        &call.callee,
        Expression::Identifier(id) if id.name == "Boolean"
    )
}

/// `JSON.stringify(x)` — preserves taint into a string. Recognised so
/// `new Response(JSON.stringify({ password: ... }))` still fires.
fn is_json_stringify(call: &CallExpression<'_>) -> bool {
    let Some(MemberExpression::StaticMemberExpression(method)) =
        call.callee.as_member_expression()
    else {
        return false;
    };
    let Expression::Identifier(root) = &method.object else {
        return false;
    };
    root.name == "JSON" && method.property.name == "stringify"
}
