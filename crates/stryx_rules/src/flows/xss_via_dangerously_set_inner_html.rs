//! `flow/xss-via-dangerously-set-inner-html` — slice 1 (single-file).
//!
//! Detects request-body-tainted values reaching React's
//! `dangerouslySetInnerHTML={{ __html: <expr> }}` JSX attribute
//! without a recognised HTML sanitiser. The sink is a JSX-attribute
//! pattern, not a call expression, so this rule doesn't contribute a
//! [`StepKind`] sink variant — the JSX walk is done inline in the
//! visitor.
//!
//! Recognised sanitisers (inline at the `__html` value site —
//! wrapping the tainted expression in one of these untaints):
//!
//! - `DOMPurify.sanitize(<expr>)` (or any `<x>.sanitize(<expr>)` where
//!   the receiver name matches `DOMPurify` or `dompurify`).
//! - `sanitizeHtml(<expr>)` / `sanitize_html(<expr>)` (bare ident).
//!
//! See `docs/rules/flow-xss-via-dangerously-set-inner-html.md` for
//! the rule's contract.

use std::collections::HashMap;

use stryx_ast::{
    Visit,
    ast::{
        Argument, ArrowFunctionExpression, AssignmentExpression, AssignmentTarget, BindingPattern,
        CallExpression, ChainElement, Expression, Function, JSXAttribute, JSXAttributeValue,
        JSXExpression, ObjectExpression, ObjectPropertyKind, PropertyKey, VariableDeclarator,
    },
    to_span,
};
use stryx_core::{Finding, Severity};

use crate::adapters::EnabledAdapters;
use crate::flows::unvalidated_body_to_db::decorated_param_names_for_adapters;
use crate::steps::sources::BodySource;
use crate::steps::{StepCtx, StepKind};
use crate::{Rule, RuleContext, RuleMeta};

const RULE_ID: &str = "flow/xss-via-dangerously-set-inner-html";

const RULE_STEPS: &[StepKind] = &[StepKind::BodySource(BodySource)];

pub struct XssViaDangerouslySetInnerHtml;

impl XssViaDangerouslySetInnerHtml {
    pub fn new() -> Self {
        Self
    }
}

impl Default for XssViaDangerouslySetInnerHtml {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for XssViaDangerouslySetInnerHtml {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: RULE_ID,
            default_severity: Severity::High,
            description: "Untrusted request input reaches React's `dangerouslySetInnerHTML` __html value without a recognised HTML sanitiser.",
        }
    }

    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding> {
        let mut visitor =
            XssVisitor::new_with_adapters(ctx.file.path.clone(), ctx.index, ctx.adapters);
        for stmt in &ctx.file.program.body {
            visitor.visit_statement(stmt);
        }
        visitor.findings
    }
}

struct XssVisitor<'idx> {
    file: std::path::PathBuf,
    scopes: Vec<HashMap<String, ()>>,
    findings: Vec<Finding>,
    /// Read-only project index. Slice 1 of this rule is single-file and
    /// the step recognisers it consults (`BodySource`) do not read
    /// `index` today — but we still thread it through so the constructor
    /// signature matches the canonical
    /// `new_with_adapters(path, index, adapters)` shape used by the
    /// flagship rule. Future cross-file extensions can drop in here
    /// without resurrecting a wider edit.
    index: Option<&'idx stryx_index::ProjectIndex>,
    /// Active stack adapters resolved from the project's
    /// `ProjectProfile`. `None` outside the production scan loop.
    /// Consumed by the body-decorated-param pre-taint pass in
    /// `visit_function` to extend `@Body()`-only recognition to every
    /// `DecoratedParam` source pattern an active adapter contributes
    /// (`@Query()` / `@Param()` / `@Headers()` / `@Req()` for the
    /// NestJS adapter, future framework decorators too).
    adapters: Option<&'idx EnabledAdapters>,
}

impl<'idx> XssVisitor<'idx> {
    #[allow(dead_code)]
    fn new(file: std::path::PathBuf, index: Option<&'idx stryx_index::ProjectIndex>) -> Self {
        Self::new_with_adapters(file, index, None)
    }

    fn new_with_adapters(
        file: std::path::PathBuf,
        index: Option<&'idx stryx_index::ProjectIndex>,
        adapters: Option<&'idx EnabledAdapters>,
    ) -> Self {
        Self {
            file,
            scopes: vec![HashMap::new()],
            findings: Vec::new(),
            index,
            adapters,
        }
    }

    fn step_ctx(&self) -> StepCtx<'_, 'idx> {
        StepCtx {
            file: &self.file,
            index: self.index,
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

    /// Body-taint walk — same shape as the other slice-1 flow rules.
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
            Expression::LogicalExpression(b) => {
                self.expr_taint(&b.left) || self.expr_taint(&b.right)
            }
            Expression::BinaryExpression(b) => {
                self.expr_taint(&b.left) || self.expr_taint(&b.right)
            }
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
            Expression::AssignmentExpression(a) => self.expr_taint(&a.right),
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
        // Sanitiser wrap drops taint through the assignment so the
        // canonical `const clean = DOMPurify.sanitize(html); … __html: clean`
        // pattern recorded in `docs/rules/flow-xss-via-dangerously-set-inner-html.md`
        // doesn't fire when the binding reaches the sink. Inline-at-sink
        // wraps still work via `is_sanitiser_call` at the JSX site.
        if is_sanitiser_call(init) {
            return;
        }
        if self.expr_taint(init) {
            self.taint_pattern(&declarator.id);
        }
    }

    /// Inspect a single JSX attribute. When the attribute is
    /// `dangerouslySetInnerHTML={{ __html: <expr> }}` and `<expr>`
    /// is body-tainted without a recognised sanitiser wrap, emit a
    /// Finding at the attribute span.
    fn check_jsx_attribute(&mut self, attr: &JSXAttribute<'_>) {
        if !attr.is_identifier("dangerouslySetInnerHTML") {
            return;
        }
        // The React typing guarantees `dangerouslySetInnerHTML`'s
        // value is `{ __html: string }`. In AST terms: an
        // ExpressionContainer wrapping an ObjectExpression with a
        // single `__html` property. Anything else is a TypeScript
        // error and not our concern.
        let Some(JSXAttributeValue::ExpressionContainer(container)) = &attr.value else {
            return;
        };
        let JSXExpression::ObjectExpression(obj) = &container.expression else {
            return;
        };
        let Some(html_expr) = html_value(obj) else {
            return;
        };
        // Sanitiser wrap drops taint regardless of inner expression.
        if is_sanitiser_call(html_expr) {
            return;
        }
        if !self.expr_taint(html_expr) {
            return;
        }
        self.findings.push(
            Finding::ast(
                RULE_ID,
                Severity::High,
                "Untrusted request input reaches `dangerouslySetInnerHTML`'s `__html` value without a recognised HTML sanitiser. Any HTML / `<script>` / event-handler the attacker submits executes in the user's session (DOM-XSS).".to_string(),
                to_span(&self.file, attr.span),
            )
            .with_help(
                "Wrap the value in `DOMPurify.sanitize(...)` (from `isomorphic-dompurify` or `dompurify`) or `sanitizeHtml(...)` (from `sanitize-html`) before assigning to `__html`. Avoid rendering user-submitted HTML directly when possible — render it as text or use a Markdown renderer with HTML disabled.",
            ),
        );
    }
}

impl<'a, 'idx> Visit<'a> for XssVisitor<'idx> {
    fn visit_function(&mut self, func: &Function<'a>, _flags: stryx_ast::ScopeFlags) {
        self.enter_fn();
        // NestJS and similar frameworks declare body sources via parameter
        // decorators (`@Body() dto: CreateUserDto`). Pre-taint any param
        // marked with a decorator the active adapter set recognises — the
        // framework will inject body data there. Without any adapter
        // (legacy test sites that build a visitor directly), only `@Body()`
        // is recognised, preserving prior behaviour for existing fixtures.
        //
        // Helper imported from the flagship rule
        // (`flows::unvalidated_body_to_db::decorated_param_names_for_adapters`)
        // rather than duplicated — single owner keeps the
        // decorator-recognition logic consistent across all body-source
        // rules during the v0.4.0 migration.
        for pname in decorated_param_names_for_adapters(&func.params, self.adapters) {
            self.taint(pname);
        }
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

    fn visit_jsx_attribute(&mut self, attr: &JSXAttribute<'a>) {
        self.check_jsx_attribute(attr);
        stryx_ast::walk::walk_jsx_attribute(self, attr);
    }

    fn visit_assignment_expression(&mut self, a: &AssignmentExpression<'a>) {
        let rhs_tainted = self.expr_taint(&a.right);
        if let AssignmentTarget::AssignmentTargetIdentifier(id) = &a.left {
            if rhs_tainted {
                self.taint(id.name.to_string());
            } else if let Some(scope) = self.scopes.last_mut() {
                scope.remove(id.name.as_str());
            }
        }
        self.visit_expression(&a.right);
    }
}

/// Find the value of the `__html` property in an object literal, if
/// present. Returns `None` for shapes that aren't a plain `{ __html: <expr> }`.
fn html_value<'a, 'b>(obj: &'a ObjectExpression<'b>) -> Option<&'a Expression<'b>> {
    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            continue;
        };
        let PropertyKey::StaticIdentifier(key) = &p.key else {
            continue;
        };
        if key.name == "__html" {
            return Some(&p.value);
        }
    }
    None
}

/// True iff `expr` is one of the recognised HTML-sanitiser call
/// shapes: `DOMPurify.sanitize(...)`, `dompurify.sanitize(...)`,
/// bare `sanitizeHtml(...)`, or bare `sanitize_html(...)`.
fn is_sanitiser_call(expr: &Expression<'_>) -> bool {
    let mut cursor = expr;
    loop {
        match cursor {
            Expression::ParenthesizedExpression(p) => cursor = &p.expression,
            Expression::TSAsExpression(t) => cursor = &t.expression,
            Expression::TSNonNullExpression(t) => cursor = &t.expression,
            Expression::TSSatisfiesExpression(t) => cursor = &t.expression,
            Expression::TSTypeAssertion(t) => cursor = &t.expression,
            Expression::AwaitExpression(a) => cursor = &a.argument,
            _ => break,
        }
    }
    let Expression::CallExpression(call) = cursor else {
        return false;
    };
    match &call.callee {
        // Bare-name sanitisers: `sanitizeHtml(html)` /
        // `sanitize_html(html)`.
        Expression::Identifier(id) => {
            matches!(id.name.as_str(), "sanitizeHtml" | "sanitize_html")
        }
        // `<receiver>.sanitize(html)` where the receiver looks like
        // DOMPurify. Match both common spellings (`DOMPurify` from
        // `isomorphic-dompurify`, lowercase `dompurify` from
        // `dompurify`).
        Expression::StaticMemberExpression(m) => {
            if m.property.name != "sanitize" {
                return false;
            }
            matches!(
                &m.object,
                Expression::Identifier(id) if id.name == "DOMPurify" || id.name == "dompurify"
            )
        }
        _ => false,
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
