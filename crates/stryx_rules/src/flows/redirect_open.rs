//! `flow/redirect-open` — slice 1 (single-file).
//!
//! Detects request-body-tainted values reaching a redirect call
//! (`NextResponse.redirect(...)`, bare `redirect(...)` from
//! `next/navigation`, `res.redirect(...)`, `Response.redirect(...)`)
//! as the target URL without a recognised allow-list sanitiser
//! along the path. Structurally identical to
//! [`crate::flows::ssrf_via_fetch`] — same source, same allow-list
//! sanitiser shapes, different sink set. The two rules share the
//! `URLAllowListSanitizer`-shaped helpers via local mirrors;
//! extracting a shared module is reserved for a third rule (the
//! third repetition is when the abstraction becomes justified).
//!
//! See `docs/rules/flow-redirect-open.md` for the rule's contract.

use std::collections::HashMap;

use stryx_ast::{
    Visit,
    ast::{
        Argument, ArrowFunctionExpression, BindingPattern, CallExpression, ChainElement,
        Expression, Function, IfStatement, ObjectPropertyKind, PropertyKey, Statement,
        UnaryOperator, VariableDeclarator,
    },
    to_span,
};
use stryx_core::{Finding, Severity};

use crate::steps::sinks::{RedirectSink, is_redirect_sink_call};
use crate::steps::sources::BodySource;
use crate::steps::{StepCtx, StepKind};
use crate::{Rule, RuleContext, RuleMeta};

const RULE_ID: &str = "flow/redirect-open";

const RULE_STEPS: &[StepKind] = &[
    StepKind::BodySource(BodySource),
    StepKind::RedirectSink(RedirectSink),
];

pub struct RedirectOpen;

impl RedirectOpen {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RedirectOpen {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RedirectOpen {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: RULE_ID,
            default_severity: Severity::High,
            description: "Untrusted request input reaches a redirect call as the target URL without an allow-list check.",
        }
    }

    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding> {
        let mut visitor = RedirectVisitor {
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

struct RedirectVisitor {
    file: std::path::PathBuf,
    scopes: Vec<HashMap<String, ()>>,
    /// URL-constructor lineage map — mirrors `SsrfVisitor.url_inits`.
    url_inits: HashMap<String, String>,
    findings: Vec<Finding>,
}

impl RedirectVisitor {
    fn step_ctx(&self) -> StepCtx<'_, 'static> {
        StepCtx {
            file: &self.file,
            index: None,
            body_source_active: true,
        }
    }

    fn enter_fn(&mut self) {
        self.scopes.push(HashMap::new());
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
        if let Some(binding) = single_binding_name(&declarator.id)
            && let Some(input_name) = extract_url_constructor_input(init)
        {
            self.url_inits.insert(binding, input_name);
        }
        if self.expr_taint(init) {
            self.taint_pattern(&declarator.id);
        }
    }

    fn check_redirect_sink(&mut self, call: &CallExpression<'_>) {
        if !is_redirect_sink_call(call) || !self.registry_as_sink(call) {
            return;
        }
        let Some(first_arg) = call.arguments.first().and_then(argument_expr) else {
            return;
        };
        if !self.expr_taint(first_arg) {
            return;
        }
        self.findings.push(
            Finding::ast(
                RULE_ID,
                Severity::High,
                "Untrusted request input reaches a redirect call as the target URL without a recognised allow-list check.".to_string(),
                to_span(&self.file, call.span),
            )
            .with_help(
                "Parse the URL with `new URL(input)` and check the host against an allow-list before redirecting. Reject anything outside the allow-list with a 4xx response.",
            ),
        );
    }
}

impl<'a> Visit<'a> for RedirectVisitor {
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
        self.check_redirect_sink(call);
        stryx_ast::walk::walk_call_expression(self, call);
    }

    fn visit_if_statement(&mut self, is: &IfStatement<'a>) {
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

// ── Local mirrors of `ssrf_via_fetch`'s allow-list helpers. ─────────
// Both rules share the same URL allow-list sanitiser shape. The
// helpers live here as local copies for now; extracting them into
// a shared `steps/sanitizers/url_allowlist.rs` becomes worthwhile
// at the third consumer (per the rule-of-three).

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
    if !matches!(&new_expr.callee, Expression::Identifier(id) if id.name == "URL") {
        return None;
    }
    let first_arg = new_expr.arguments.first().and_then(argument_expr)?;
    extract_underlying_ident(first_arg)
}

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
