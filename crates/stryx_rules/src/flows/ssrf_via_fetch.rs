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
        Expression, Function, ObjectPropertyKind, PropertyKey, VariableDeclarator,
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
    }

    fn exit_fn(&mut self) {
        self.scopes.pop();
    }

    fn taint(&mut self, name: String) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name, ());
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
        self.findings.push(
            Finding::ast(
                RULE_ID,
                Severity::High,
                "Untrusted request input reaches an outbound HTTP call as the URL without a recognised allow-list check.".to_string(),
                to_span(&self.file, call.span),
            )
            .with_help(
                "Parse the URL with `new URL(input)` and check the host against an allow-list before calling fetch/axios/got. Reject anything outside the allow-list with a 4xx response.",
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
