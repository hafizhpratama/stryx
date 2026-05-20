//! `flow/insecure-deserialize` — single-file slice 1.
//!
//! Detects request-body-tainted values flowing into one of the
//! recognised unsafe-deserialization sinks. The sink set (and the
//! explicit exclusion list) lives in
//! [`crate::steps::sinks::deserialize`]; the rule here owns only
//! the body-taint walk and the finding emission.
//!
//! This is a single-file rule on purpose. The sinks are all
//! direct RCE; if body data reaches them in the same handler that
//! receives it, that's a high-signal finding without needing
//! cross-file taint summaries. Helper-routed cases are deferred
//! to a future slice if real-world fixtures motivate it.
//!
//! See `docs/rules/flow-insecure-deserialize.md` for the rule's
//! contract and the bad/good fixtures it pins.

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
// Reuse the canonical decorator pre-taint helper from the flagship
// `flow/unvalidated-body-to-db` rule. Keeping a single implementation
// avoids drift on what counts as a body-decorated param across rules.
use crate::flows::unvalidated_body_to_db::decorated_param_names_for_adapters;
use crate::steps::sinks::deserialize::is_deserialize_sink_call;
use crate::steps::sources::BodySource;
use crate::steps::{StepCtx, StepKind};
use crate::{Rule, RuleContext, RuleMeta};

const RULE_ID: &str = "flow/insecure-deserialize";

// Only `BodySource` participates in the registry walk — the
// deserialize sink is dispatched directly via
// `is_deserialize_sink_call` (the substrate `StepKind` enum is
// closed-set and out-of-scope for this slice to extend).
const RULE_STEPS: &[StepKind] = &[StepKind::BodySource(BodySource)];

pub struct InsecureDeserialize;

impl InsecureDeserialize {
    pub fn new() -> Self {
        Self
    }
}

impl Default for InsecureDeserialize {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for InsecureDeserialize {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: RULE_ID,
            default_severity: Severity::Critical,
            description: "Untrusted request input reaches an unsafe-deserialization sink (node-serialize unserialize, js-yaml load, or vm.runInX) — arbitrary code execution under the application's process identity.",
        }
    }

    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding> {
        let mut visitor = InsecureDeserializeVisitor::new_with_adapters(
            ctx.file.path.clone(),
            ctx.index,
            ctx.adapters,
        );
        for stmt in &ctx.file.program.body {
            visitor.visit_statement(stmt);
        }
        visitor.findings
    }
}

struct InsecureDeserializeVisitor<'idx> {
    file: PathBuf,
    scopes: Vec<HashMap<String, ()>>,
    findings: Vec<Finding>,
    /// Read-only project index. Single-file slice doesn't consult
    /// it, but the constructor takes it to match the canonical
    /// `new_with_adapters(path, index, adapters)` shape so future
    /// cross-file extensions don't require a wider edit.
    index: Option<&'idx stryx_index::ProjectIndex>,
    /// Active stack adapters, consumed by the decorated-param
    /// pre-taint pass in `visit_function`.
    adapters: Option<&'idx EnabledAdapters>,
}

impl<'idx> InsecureDeserializeVisitor<'idx> {
    fn new_with_adapters(
        file: PathBuf,
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
        if self.expr_taint(init) {
            self.taint_pattern(&declarator.id);
        }
    }

    fn check_deserialize_sink(&mut self, call: &CallExpression<'_>) {
        if !is_deserialize_sink_call(call) {
            return;
        }
        // The first argument is the payload being deserialized
        // (the source string for `vm.runInX`, the buffer for
        // `unserialize`, the document for `yaml.load`). Body taint
        // there is the rule's finding condition.
        let Some(first_arg) = call.arguments.first().and_then(argument_expr) else {
            return;
        };
        if !self.expr_taint(first_arg) {
            return;
        }
        self.findings.push(
            Finding::ast(
                RULE_ID,
                Severity::Critical,
                "Untrusted request input reaches an unsafe-deserialization sink. \
                 `node-serialize.unserialize`, `js-yaml`'s `yaml.load`, and Node's `vm.runInX` \
                 all evaluate attacker-controlled payloads as code — arbitrary code execution \
                 under the application's process identity (OWASP A08:2021 / CWE-502)."
                    .to_string(),
                to_span(&self.file, call.span),
            )
            .with_help(
                "Do not deserialise untrusted data through code-executing APIs. \
                 Use `JSON.parse` for JSON payloads and validate the parsed shape with a schema \
                 (zod, valibot). For YAML use `yaml.safeLoad` (or the `FAILSAFE_SCHEMA` option). \
                 Never pass request input to `vm.runInNewContext` / `runInThisContext` / \
                 `runInContext` — there is no safe-list defence for arbitrary script evaluation.",
            ),
        );
    }
}

impl<'a, 'idx> Visit<'a> for InsecureDeserializeVisitor<'idx> {
    fn visit_function(&mut self, func: &Function<'a>, _flags: stryx_ast::ScopeFlags) {
        self.enter_fn();
        // NestJS and similar frameworks declare body sources via parameter
        // decorators (`@Body() dto: CreateUserDto`). Pre-taint any param
        // whose decorator the active adapter set recognises.
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
        self.check_deserialize_sink(call);
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
