//! `flow/ssrf-via-fetch` — slice 1 (single-file).
//!
//! Detects request-body-tainted values reaching an outbound HTTP
//! call (`fetch`, `axios.<method>`, `got`) as the URL argument
//! without a recognised allow-list sanitiser along the path. Slice
//! 1 is single-file only — cross-file taint via summaries lands in
//! slice 2 once a real-world consumer motivates the engineering.
//!
//! See `docs/rules/flow-ssrf-via-fetch.md` for the rule's contract
//! and the bad/good fixtures it pins.

use std::collections::HashMap;

use stryx_ast::{
    Visit,
    ast::{
        Argument, ArrowFunctionExpression, BindingPattern, CallExpression, ChainElement,
        Expression, Function, IfStatement, NewExpression, ObjectPropertyKind, PropertyKey,
        Statement, UnaryOperator, VariableDeclarator,
    },
    to_span,
};
use stryx_core::{Finding, Severity};

use crate::steps::sinks::{FetchSink, is_http_sink_call};
use crate::steps::sources::BodySource;
use crate::steps::{StepCtx, StepKind};
use crate::{Rule, RuleContext, RuleMeta};

const RULE_ID: &str = "flow/ssrf-via-fetch";

/// Step registry consulted by [`SsrfVisitor`]. Body taint flows
/// from [`BodySource`] into the URL argument of [`FetchSink`]-shaped
/// calls; slice 1 records no sanitiser steps yet (URL allow-list
/// recognition is slice 2).
const RULE_STEPS: &[StepKind] = &[
    StepKind::BodySource(BodySource),
    StepKind::FetchSink(FetchSink),
];

pub struct SsrfViaFetch;

impl SsrfViaFetch {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SsrfViaFetch {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SsrfViaFetch {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: RULE_ID,
            default_severity: Severity::High,
            description: "Untrusted request input reaches an outbound HTTP call as the URL without an allow-list check.",
        }
    }

    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding> {
        let mut visitor = SsrfVisitor {
            file: ctx.file.path.clone(),
            scopes: vec![HashMap::new()],
            url_inits: HashMap::new(),
            findings: Vec::new(),
        };
        for stmt in &ctx.file.program.body {
            visitor.visit_statement(stmt);
        }
        visitor.findings
    }
}

struct SsrfVisitor {
    file: std::path::PathBuf,
    /// Stack of per-function scopes; each scope maps binding name to
    /// `()` if that binding holds body-tainted data. Body-tainted
    /// shapes are over-approximated as whole-value taint for slice
    /// 1 — `const { url } = body` propagates taint to `url` even
    /// though only the `.url` member is structurally tainted.
    scopes: Vec<HashMap<String, ()>>,
    /// Slice 2 — URL-constructor lineage. Maps a binding name to
    /// the original ident passed into `new URL(...)`. Populated at
    /// var-decl sites of the shape `const parsed = new URL(input)`.
    /// Consumed by `visit_if_statement` when an allow-list guard
    /// (`if (!ALLOWED.has(parsed.host)) return ...`) proves the
    /// underlying input has been validated against an allow-list.
    /// Per-function — cleared in `enter_fn`.
    url_inits: HashMap<String, String>,
    findings: Vec<Finding>,
}

impl SsrfVisitor {
    fn step_ctx(&self) -> StepCtx<'_, 'static> {
        StepCtx {
            file: &self.file,
            index: None,
            body_source_active: true,
        }
    }

    fn enter_fn(&mut self) {
        self.scopes.push(HashMap::new());
        // URL-constructor lineage is per-function. A binding declared
        // inside one function should not leak its (parsed, input)
        // mapping into the next function the visitor walks.
        self.url_inits.clear();
    }

    fn exit_fn(&mut self) {
        self.scopes.pop();
    }

    fn taint(&mut self, name: String) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name, ());
        }
    }

    fn untaint(&mut self, name: &str) {
        for scope in self.scopes.iter_mut().rev() {
            if scope.remove(name).is_some() {
                return;
            }
        }
    }

    fn is_tainted(&self, name: &str) -> bool {
        self.scopes.iter().rev().any(|s| s.contains_key(name))
    }

    fn registry_as_source(&self, expr: &Expression<'_>) -> bool {
        let ctx = self.step_ctx();
        RULE_STEPS.iter().any(|s| s.as_source(&ctx, expr).is_some())
    }

    fn registry_as_call_source(&self, call: &CallExpression<'_>) -> bool {
        let ctx = self.step_ctx();
        RULE_STEPS
            .iter()
            .any(|s| s.as_call_source(&ctx, call).is_some())
    }

    fn registry_as_sink(&self, call: &CallExpression<'_>) -> bool {
        let ctx = self.step_ctx();
        RULE_STEPS.iter().any(|s| s.as_sink(&ctx, call).is_some())
    }

    /// Returns `true` if `expr` carries body taint. Mirrors the
    /// structural-propagator walk used by `flow/unvalidated-body-to-db`
    /// but with slice 1's narrower coverage: no call-summary lookup,
    /// no validators, no chain-element subtleties beyond unwrap.
    fn expr_taint(&self, expr: &Expression<'_>) -> bool {
        match expr {
            Expression::Identifier(id) => self.is_tainted(id.name.as_str()),
            Expression::AwaitExpression(a) => self.expr_taint(&a.argument),
            Expression::ParenthesizedExpression(p) => self.expr_taint(&p.expression),
            Expression::TSAsExpression(t) => self.expr_taint(&t.expression),
            Expression::TSNonNullExpression(t) => self.expr_taint(&t.expression),
            Expression::TSSatisfiesExpression(t) => self.expr_taint(&t.expression),
            Expression::TSTypeAssertion(t) => self.expr_taint(&t.expression),
            Expression::CallExpression(call) => {
                self.registry_as_call_source(call)
                    || call
                        .arguments
                        .iter()
                        .filter_map(argument_expr)
                        .any(|e| self.expr_taint(e))
            }
            Expression::StaticMemberExpression(m) => {
                self.registry_as_source(expr) || self.expr_taint(&m.object)
            }
            Expression::ComputedMemberExpression(m) => self.expr_taint(&m.object),
            Expression::PrivateFieldExpression(m) => self.expr_taint(&m.object),
            Expression::TemplateLiteral(t) => t.expressions.iter().any(|e| self.expr_taint(e)),
            Expression::TaggedTemplateExpression(t) => {
                t.quasi.expressions.iter().any(|e| self.expr_taint(e))
            }
            Expression::ObjectExpression(obj) => obj.properties.iter().any(|p| match p {
                ObjectPropertyKind::ObjectProperty(p) => self.expr_taint(&p.value),
                ObjectPropertyKind::SpreadProperty(s) => self.expr_taint(&s.argument),
            }),
            Expression::ArrayExpression(arr) => arr
                .elements
                .iter()
                .any(|el| el.as_expression().is_some_and(|e| self.expr_taint(e))),
            Expression::ConditionalExpression(c) => {
                self.expr_taint(&c.consequent) || self.expr_taint(&c.alternate)
            }
            Expression::LogicalExpression(b) => self.expr_taint(&b.left) || self.expr_taint(&b.right),
            Expression::BinaryExpression(b) => self.expr_taint(&b.left) || self.expr_taint(&b.right),
            Expression::ChainExpression(c) => match &c.expression {
                ChainElement::CallExpression(call) => {
                    self.registry_as_call_source(call)
                        || call
                            .arguments
                            .iter()
                            .filter_map(argument_expr)
                            .any(|e| self.expr_taint(e))
                }
                ChainElement::StaticMemberExpression(m) => self.expr_taint(&m.object),
                ChainElement::ComputedMemberExpression(m) => self.expr_taint(&m.object),
                ChainElement::PrivateFieldExpression(m) => self.expr_taint(&m.object),
                ChainElement::TSNonNullExpression(t) => self.expr_taint(&t.expression),
            },
            _ => false,
        }
    }

    /// Record taint on `pat` from a tainted RHS expression. Handles
    /// bare identifier (`const x = body`) and destructured-object
    /// shorthand (`const { url } = body` — `url` becomes tainted).
    /// Array patterns and rest elements are conservatively over-
    /// tainted: every named binding gets the taint.
    fn taint_pattern(&mut self, pat: &BindingPattern<'_>) {
        let mut names = Vec::new();
        collect_binding_names(pat, &mut names);
        for n in names {
            self.taint(n);
        }
    }

    fn handle_var_decl(&mut self, declarator: &VariableDeclarator<'_>) {
        let Some(init) = &declarator.init else {
            return;
        };
        // Slice 2 — track `const parsed = new URL(INPUT)` lineage.
        // Recorded unconditionally; the consumer at the IfStatement
        // narrowing site only fires when the structural guard
        // matches. INPUT can be either a bare ident or a member
        // chain — we want to remember the bare-ident root so the
        // guard can untaint the right binding.
        if let Some(binding) = single_binding_name(&declarator.id)
            && let Some(input_name) = extract_url_constructor_input(init)
        {
            self.url_inits.insert(binding, input_name);
        }
        if self.expr_taint(init) {
            self.taint_pattern(&declarator.id);
        }
    }

    fn check_http_sink(&mut self, call: &CallExpression<'_>) {
        if !is_http_sink_call(call) || !self.registry_as_sink(call) {
            return;
        }
        let Some(first_arg) = call.arguments.first().and_then(argument_expr) else {
            return;
        };
        if !self.expr_taint(first_arg) {
            return;
        }
        // Severity tier — distinguish full-URL SSRF from
        // path-injection within a fixed host. When the first arg is
        // a template literal whose leading quasi pins the URL scheme
        // and host (`https://example.com/...`), the body data fills
        // only a path/query slot — bounded blast radius, downgrade
        // to Medium. Bare-ident shapes (`fetch(body.url)`) are
        // full SSRF, host-arbitrary → High.
        let (severity, message) = if is_host_pinned_template(first_arg) {
            (
                Severity::Medium,
                "Untrusted request input reaches an outbound HTTP call as a path/query segment within a fixed-host URL — path-injection surface against the pinned API.".to_string(),
            )
        } else {
            (
                Severity::High,
                "Untrusted request input reaches an outbound HTTP call as the URL without a recognised allow-list check.".to_string(),
            )
        };
        self.findings.push(
            Finding::ast(RULE_ID, severity, message, to_span(&self.file, call.span))
                .with_help(
                    "Parse the URL with `new URL(input)` and check the host against an allow-list before calling fetch/axios/got. For path-segment substitution, validate against an allow-list of expected path values and reject anything else with a 4xx response.",
                ),
        );
    }
}

impl<'a> Visit<'a> for SsrfVisitor {
    fn visit_function(&mut self, func: &Function<'a>, _flags: stryx_ast::ScopeFlags) {
        self.enter_fn();
        if let Some(body) = &func.body {
            for stmt in &body.statements {
                self.visit_statement(stmt);
            }
        }
        self.exit_fn();
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        self.enter_fn();
        for stmt in &arrow.body.statements {
            self.visit_statement(stmt);
        }
        self.exit_fn();
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        self.handle_var_decl(declarator);
        if let Some(init) = &declarator.init {
            self.visit_expression(init);
        }
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        self.check_http_sink(call);
        // Continue walking to find nested sinks (e.g. `fetch(maybe(body))`).
        stryx_ast::walk::walk_call_expression(self, call);
    }

    fn visit_if_statement(&mut self, is: &IfStatement<'a>) {
        // Slice 2 — URL allow-list guard narrowing. Pattern:
        //
        //   const parsed = new URL(input);
        //   if (!ALLOWED.has(parsed.host)) {
        //     return ...;
        //   }
        //   // past here, `input` is allow-listed
        //
        // Mirrors the discriminated-union validator pattern
        // (task #96) — track lineage at the var-decl site, consume
        // it at the narrowing site, untaint past the early return.
        if let Some(url_binding) = match_url_allow_list_guard(&is.test)
            && let Some(input_name) = self.url_inits.get(&url_binding).cloned()
            && branch_returns(&is.consequent)
        {
            self.untaint(&input_name);
            self.untaint(&url_binding);
        }
        stryx_ast::walk::walk_if_statement(self, is);
    }
}

fn argument_expr<'a, 'b>(arg: &'a Argument<'b>) -> Option<&'a Expression<'b>> {
    match arg {
        Argument::SpreadElement(_) => None,
        _ => arg.as_expression(),
    }
}

fn collect_binding_names(pat: &BindingPattern<'_>, out: &mut Vec<String>) {
    match pat {
        BindingPattern::BindingIdentifier(id) => out.push(id.name.to_string()),
        BindingPattern::ObjectPattern(o) => {
            for prop in &o.properties {
                collect_binding_names(&prop.value, out);
                if let PropertyKey::StaticIdentifier(id) = &prop.key
                    && prop.shorthand
                {
                    out.push(id.name.to_string());
                }
            }
        }
        BindingPattern::ArrayPattern(a) => {
            for b in a.elements.iter().flatten() {
                collect_binding_names(b, out);
            }
        }
        BindingPattern::AssignmentPattern(a) => collect_binding_names(&a.left, out),
    }
}

fn single_binding_name(pat: &BindingPattern<'_>) -> Option<String> {
    if let BindingPattern::BindingIdentifier(id) = pat {
        Some(id.name.to_string())
    } else {
        None
    }
}

/// Slice 2 — recognise `new URL(IDENT)` and return IDENT's name.
/// Drills through trivial wrappers (`await`, parens, TS casts) on
/// both the outer expression and the first argument so common
/// shapes like `new URL(input as string)` resolve correctly.
fn extract_url_constructor_input(expr: &Expression<'_>) -> Option<String> {
    let mut cursor = expr;
    loop {
        match cursor {
            Expression::AwaitExpression(a) => cursor = &a.argument,
            Expression::ParenthesizedExpression(p) => cursor = &p.expression,
            Expression::TSAsExpression(t) => cursor = &t.expression,
            Expression::TSNonNullExpression(t) => cursor = &t.expression,
            Expression::TSSatisfiesExpression(t) => cursor = &t.expression,
            Expression::TSTypeAssertion(t) => cursor = &t.expression,
            _ => break,
        }
    }
    let Expression::NewExpression(new_expr) = cursor else {
        return None;
    };
    if !is_url_callee(&new_expr.callee) {
        return None;
    }
    let first_arg = new_expr.arguments.first().and_then(argument_expr)?;
    extract_underlying_ident(first_arg)
}

/// True iff the callee of a `new` expression is the global `URL`
/// constructor. Bare `URL` only — qualified shapes like
/// `globalThis.URL` are uncommon enough to skip in slice 2.
fn is_url_callee(callee: &Expression<'_>) -> bool {
    matches!(callee, Expression::Identifier(id) if id.name == "URL")
}

/// Drill through trivial wrappers (parens, TS casts) and return
/// the underlying bare-identifier name, or `None` if the expression
/// is not a wrapped identifier.
fn extract_underlying_ident(expr: &Expression<'_>) -> Option<String> {
    let mut cursor = expr;
    loop {
        match cursor {
            Expression::Identifier(id) => return Some(id.name.to_string()),
            Expression::ParenthesizedExpression(p) => cursor = &p.expression,
            Expression::TSAsExpression(t) => cursor = &t.expression,
            Expression::TSNonNullExpression(t) => cursor = &t.expression,
            Expression::TSSatisfiesExpression(t) => cursor = &t.expression,
            Expression::TSTypeAssertion(t) => cursor = &t.expression,
            _ => return None,
        }
    }
}

/// Slice 2 / 3 — match the canonical URL allow-list guard. Returns
/// the URL-binding's name on match. Recognised callee shapes
/// (negated-only — early-return on disallowed):
///
/// - `!ALLOWED.has(IDENT.host)` — `Set.has` / `Map.has`
/// - `!ALLOWED.includes(IDENT.hostname)` — `Array.includes`
/// - `!ALLOWED.includes(IDENT.origin)`
/// - `!validatorFn(IDENT.host)` where `validatorFn` is a bare
///   identifier starting with `isAllowed` / `isValid` / `validate`
///   / `verify` / `check` (slice 3 — validator-function form).
///
/// In all shapes, the call's first argument must be a static-member
/// access of the form `IDENT.host` / `IDENT.hostname` /
/// `IDENT.origin` — IDENT being the binding the visitor's
/// `url_inits` map tracks back to the original URL input.
///
/// Positive-form guards (`if (ALLOWED.has(parsed.host)) { fetch }`)
/// are deferred — they require tracking the consequent's narrowed
/// branch instead of the post-If continuation.
fn match_url_allow_list_guard(test: &Expression<'_>) -> Option<String> {
    let Expression::UnaryExpression(unary) = test else {
        return None;
    };
    if unary.operator != UnaryOperator::LogicalNot {
        return None;
    }
    let mut cursor = &unary.argument;
    while let Expression::ParenthesizedExpression(p) = cursor {
        cursor = &p.expression;
    }
    let Expression::CallExpression(call) = cursor else {
        return None;
    };
    // Callee shape — either `X.has` / `X.includes`, or a bare
    // validator-named identifier (slice 3).
    let callee_ok = match &call.callee {
        Expression::StaticMemberExpression(callee) => {
            matches!(callee.property.name.as_str(), "has" | "includes")
        }
        Expression::Identifier(id) => is_validator_callee_name(id.name.as_str()),
        _ => false,
    };
    if !callee_ok {
        return None;
    }
    // First argument must be `IDENT.host` / `IDENT.hostname` /
    // `IDENT.origin` — the URL-binding's member access.
    let arg = call.arguments.first().and_then(argument_expr)?;
    let mut cursor = arg;
    while let Expression::ParenthesizedExpression(p) = cursor {
        cursor = &p.expression;
    }
    let Expression::StaticMemberExpression(m) = cursor else {
        return None;
    };
    if !matches!(m.property.name.as_str(), "host" | "hostname" | "origin") {
        return None;
    }
    let Expression::Identifier(id) = &m.object else {
        return None;
    };
    Some(id.name.to_string())
}

/// Slice 3 — true iff `name` looks like a host-validator function
/// (leading camelCase word from `isAllowed`/`isValid`/`validate`/
/// `verify`/`check`). The boundary requires the next char to be
/// ASCII-uppercase or end-of-name so `validating` doesn't match.
fn is_validator_callee_name(name: &str) -> bool {
    const PREFIXES: &[&str] = &["isAllowed", "isValid", "validate", "verify", "check"];
    PREFIXES.iter().any(|prefix| {
        if name.len() < prefix.len() {
            return false;
        }
        let (head, tail) = name.split_at(prefix.len());
        if !head.eq_ignore_ascii_case(prefix) {
            return false;
        }
        tail.is_empty() || tail.chars().next().is_some_and(|c| c.is_ascii_uppercase())
    })
}

/// True iff `branch` is guaranteed to leave the enclosing scope —
/// a bare return/throw statement, or a block whose first statement
/// is one. Mirrors `flow/unvalidated-body-to-db`'s `branch_returns`
/// for the discriminated-union validator pattern.
fn branch_returns(branch: &Statement<'_>) -> bool {
    match branch {
        Statement::ReturnStatement(_) | Statement::ThrowStatement(_) => true,
        Statement::BlockStatement(bs) => bs
            .body
            .iter()
            .any(|s| matches!(s, Statement::ReturnStatement(_) | Statement::ThrowStatement(_))),
        _ => false,
    }
}

/// True iff `expr` is a template literal whose leading static quasi
/// pins a URL scheme + host — `https://example.com/...` or
/// `http://example.com/...`. In that shape, body-tainted
/// interpolations can only inject into the path/query, not control
/// the destination host. Used by `check_http_sink` to downgrade
/// the severity from High (full SSRF) to Medium (path-injection).
///
/// Recognition is intentionally conservative: requires a literal
/// scheme prefix AND at least one host-like character following the
/// scheme inside the same quasi (so the host name is not itself an
/// interpolation slot like `https://${body.host}/...`).
fn is_host_pinned_template(expr: &Expression<'_>) -> bool {
    let mut cursor = expr;
    loop {
        match cursor {
            Expression::ParenthesizedExpression(p) => cursor = &p.expression,
            Expression::TSAsExpression(t) => cursor = &t.expression,
            Expression::TSNonNullExpression(t) => cursor = &t.expression,
            Expression::TSSatisfiesExpression(t) => cursor = &t.expression,
            Expression::TSTypeAssertion(t) => cursor = &t.expression,
            _ => break,
        }
    }
    let Expression::TemplateLiteral(t) = cursor else {
        return false;
    };
    // The leading quasi is the literal text before the first
    // `${...}` interpolation. For a host-pinned template that's
    // where the scheme+host live.
    let Some(leading) = t.quasis.first() else {
        return false;
    };
    let raw = leading.value.cooked.as_deref().unwrap_or("");
    if !(raw.starts_with("https://") || raw.starts_with("http://")) {
        return false;
    }
    // After the scheme there must be at least one host character
    // before the first path separator — guarding against shapes
    // like `https://${body.host}/...` where the host is itself
    // interpolated.
    let after_scheme = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"))
        .unwrap_or("");
    after_scheme
        .chars()
        .take_while(|c| *c != '/')
        .any(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

// Re-export under a local module-private alias so the type is
// load-bearing for the helpers above. `NewExpression` arrives via
// the central `ast` import; this is just to silence the
// unused-import lint when the new-construct path is the only user.
#[allow(dead_code)]
type _NewExprAlias<'a> = NewExpression<'a>;
