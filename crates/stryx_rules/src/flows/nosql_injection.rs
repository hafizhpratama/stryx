//! `flow/nosql-injection` — single-file slice.
//!
//! Detects request-body-tainted values flowing into a MongoDB query
//! filter document, where the attack class is operator injection:
//! sending `{ "$gt": "" }` (or `$ne` / `$where` / `$regex` / …) as a
//! body field turns `{ login: req.body.login }` into a filter that
//! matches every document.
//!
//! Recognised sinks live in [`crate::steps::sinks::nosql`]. The
//! recogniser is intentionally conservative on the receiver shape
//! (any `<ident>.find(...)`, `<chain>.findOne(...)`, etc.) and
//! load-bearingly strict on the *first argument*: it must be an
//! object literal. That single gate eliminates the entire
//! `Array.prototype.find(callback)` false positive class.
//!
//! Single-file only for slice 1 — there is no extract pass and no
//! cross-file taint summary. Pull body data and pass it directly
//! into the filter in the same function to trip the rule. The
//! `flow/unvalidated-body-to-db` rule remains the home of
//! cross-file body-to-database flows; this rule's contribution is
//! the operator-injection-specific sink class plus a clearer
//! finding message.
//!
//! See `docs/rules/flow-nosql-injection.md` for the rule's contract
//! and the bad/good fixtures it pins.

use std::collections::HashMap;
use std::path::PathBuf;

use stryx_ast::{
    Visit,
    ast::{
        Argument, ArrowFunctionExpression, AssignmentExpression, AssignmentTarget, BindingPattern,
        CallExpression, ChainElement, Expression, Function, ObjectPropertyKind, PropertyKey,
        VariableDeclarator,
    },
    to_span,
};
use stryx_core::{Finding, Severity};

use crate::adapters::EnabledAdapters;
use crate::flows::unvalidated_body_to_db::decorated_param_names_for_adapters;
use crate::steps::sanitizers::parser::is_sanitizer_call;
use crate::steps::sinks::nosql::is_nosql_query_sink_call;
use crate::steps::sources::body::{is_body_source_call, is_request_body_member};
use crate::{ExtractOutput, Rule, RuleContext, RuleMeta};

const RULE_ID: &str = "flow/nosql-injection";

pub struct NoSqlInjection;

impl NoSqlInjection {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NoSqlInjection {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NoSqlInjection {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: RULE_ID,
            default_severity: Severity::High,
            description: "Untrusted request input flows into a MongoDB query filter without scalar-type coercion, enabling operator injection ({\"$gt\": \"\"}, {\"$ne\": null}).",
        }
    }

    fn extract<'a, 'b>(&self, _ctx: &RuleContext<'a, 'b>) -> ExtractOutput {
        None
    }

    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding> {
        let mut visitor = NoSqlVisitor::new(ctx.file.path.clone(), ctx.adapters);
        for stmt in &ctx.file.program.body {
            visitor.visit_statement(stmt);
        }
        visitor.findings
    }
}

struct NoSqlVisitor<'idx> {
    file: PathBuf,
    /// Stack of per-function scopes. Each scope maps binding name to
    /// `()` when that binding holds body-tainted data.
    scopes: Vec<HashMap<String, ()>>,
    /// Active stack adapters resolved from the project's
    /// `ProjectProfile`. Drives decorator-source recognition for
    /// NestJS-style `@Body() / @Query() / @Param()` parameters via
    /// the shared helper from `unvalidated_body_to_db`.
    adapters: Option<&'idx EnabledAdapters>,
    findings: Vec<Finding>,
}

impl<'idx> NoSqlVisitor<'idx> {
    fn new(file: PathBuf, adapters: Option<&'idx EnabledAdapters>) -> Self {
        Self {
            file,
            scopes: vec![HashMap::new()],
            adapters,
            findings: Vec::new(),
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

    /// `req.body` / `c.req.json()` recognition. Local rather than
    /// going through the `StepKind` registry — registration of the
    /// `NoSqlSink` step variant is the integrator's job.
    fn is_body_source(&self, expr: &Expression<'_>) -> bool {
        match expr {
            Expression::StaticMemberExpression(m) => {
                is_request_body_member(&m.object, m.property.name.as_str())
            }
            Expression::CallExpression(c) => is_body_source_call(c),
            Expression::AwaitExpression(a) => self.is_body_source(&a.argument),
            _ => false,
        }
    }

    /// True iff `expr` evaluates to body-tainted data. Mirrors the
    /// shape walk in the sibling flow rules — identifiers, member
    /// chains rooted at a tainted binding, the body source itself,
    /// and the TS-cast / await / template passthroughs.
    fn expr_taint(&self, expr: &Expression<'_>) -> bool {
        match expr {
            Expression::Identifier(id) => self.is_tainted(id.name.as_str()),
            Expression::AwaitExpression(a) => self.expr_taint(&a.argument),
            Expression::ParenthesizedExpression(p) => self.expr_taint(&p.expression),
            Expression::TSAsExpression(t) => self.expr_taint(&t.expression),
            Expression::TSNonNullExpression(t) => self.expr_taint(&t.expression),
            Expression::TSSatisfiesExpression(t) => self.expr_taint(&t.expression),
            Expression::TSTypeAssertion(t) => self.expr_taint(&t.expression),
            Expression::StaticMemberExpression(m) => {
                self.is_body_source(expr) || self.expr_taint(&m.object)
            }
            Expression::ComputedMemberExpression(m) => self.expr_taint(&m.object),
            Expression::CallExpression(call) => {
                // Scalar-coercion constructors (`String(x)`, `Number(x)`,
                // `Boolean(x)`) collapse operator-injection payloads
                // into primitives — that *is* the fix. Schema-parser
                // calls (zod `safeParse`, valibot `parse`, …) return
                // a validated value of the declared shape. Both
                // produce untainted output regardless of input.
                if is_scalar_coercion_call(call) || is_sanitizer_call(call) {
                    false
                } else {
                    self.is_body_source(expr)
                        || call
                            .arguments
                            .iter()
                            .filter_map(argument_expr)
                            .any(|e| self.expr_taint(e))
                }
            }
            Expression::ChainExpression(c) => match &c.expression {
                ChainElement::CallExpression(call) => call
                    .arguments
                    .iter()
                    .filter_map(argument_expr)
                    .any(|e| self.expr_taint(e)),
                ChainElement::StaticMemberExpression(m) => self.expr_taint(&m.object),
                ChainElement::ComputedMemberExpression(m) => self.expr_taint(&m.object),
                _ => false,
            },
            Expression::TemplateLiteral(t) => t.expressions.iter().any(|e| self.expr_taint(e)),
            Expression::ConditionalExpression(c) => {
                self.expr_taint(&c.consequent) || self.expr_taint(&c.alternate)
            }
            Expression::LogicalExpression(b) => {
                self.expr_taint(&b.left) || self.expr_taint(&b.right)
            }
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
        if self.expr_taint(init) {
            self.taint_pattern(&declarator.id);
        }
    }

    /// Emit a finding when the call is a recognised MongoDB
    /// collection method whose first-argument object literal has at
    /// least one property value carrying body taint. The sink
    /// predicate already guarantees the first argument is an
    /// object expression — we still pattern-match to walk it.
    fn check_nosql_sink(&mut self, call: &CallExpression<'_>) {
        if !is_nosql_query_sink_call(call) {
            return;
        }
        let Some(first_arg) = call.arguments.first().and_then(argument_expr) else {
            return;
        };
        let Expression::ObjectExpression(obj) = first_arg else {
            return;
        };
        let mut tainted_field: Option<String> = None;
        for prop in &obj.properties {
            match prop {
                ObjectPropertyKind::ObjectProperty(p) => {
                    if self.expr_taint(&p.value) {
                        tainted_field = Some(property_label(&p.key));
                        break;
                    }
                }
                ObjectPropertyKind::SpreadProperty(s) => {
                    if self.expr_taint(&s.argument) {
                        tainted_field = Some("<spread>".to_string());
                        break;
                    }
                }
            }
        }
        let Some(field) = tainted_field else {
            return;
        };
        self.findings.push(
            Finding::ast(
                RULE_ID,
                Severity::High,
                format!(
                    "Untrusted request input flows into a MongoDB query filter at property `{field}` without scalar-type coercion. An attacker can submit `{{\"$gt\": \"\"}}` or `{{\"$ne\": null}}` to bypass the intended equality check and match arbitrary documents (OWASP A03 / CWE-943)."
                ),
                to_span(&self.file, call.span),
            )
            .with_help(
                "Coerce the value to its expected scalar type before passing it to the query — `String(req.body.login)` for strings, `Number(req.body.id)` for numerics — or validate the body shape with a schema (zod/joi/class-validator) so non-scalar payloads are rejected at the boundary.",
            ),
        );
    }
}

impl<'a, 'idx> Visit<'a> for NoSqlVisitor<'idx> {
    fn visit_function(&mut self, func: &Function<'a>, _flags: stryx_ast::ScopeFlags) {
        self.enter_fn();
        // NestJS-style decorator pre-taint via the shared helper —
        // `@Body() / @Query() / @Param() / @Headers() / @Req()`.
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

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        self.check_nosql_sink(call);
        stryx_ast::walk::walk_call_expression(self, call);
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

/// `String(x)` / `Number(x)` / `Boolean(x)` — scalar-coercion
/// constructors that defuse operator-injection payloads. The
/// driver receives the primitive shape it expected, so even a
/// `{$gt: ""}` body collapses to an inert string. The recogniser
/// is bare-identifier-only by design; `globalThis.String(x)` and
/// re-exports would need broader recognition that does not pull
/// its weight at slice 1.
fn is_scalar_coercion_call(call: &CallExpression<'_>) -> bool {
    matches!(
        &call.callee,
        Expression::Identifier(id)
            if matches!(id.name.as_str(), "String" | "Number" | "Boolean")
    )
}

/// Render a property key for the finding message. Static idents and
/// string literals print verbatim; anything else falls back to a
/// generic placeholder.
fn property_label(key: &PropertyKey<'_>) -> String {
    match key {
        PropertyKey::StaticIdentifier(id) => id.name.to_string(),
        PropertyKey::StringLiteral(s) => s.value.to_string(),
        _ => "<computed>".to_string(),
    }
}
