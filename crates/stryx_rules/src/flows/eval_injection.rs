//! `flow/eval-injection` — slice 1 (single-file).
//!
//! Detects request-body-tainted values reaching JavaScript's dynamic
//! code-execution APIs:
//!
//! - `eval(<tainted>)`
//! - `Function(<tainted>)` / `new Function(<tainted>)` — Function
//!   constructor; the body string is parsed and bound to a callable.
//! - `setTimeout(<tainted>, ...)` / `setInterval(<tainted>, ...)` —
//!   the "implied eval" shape where the first argument is a STRING
//!   payload (not an inline function or arrow). The benign
//!   `setTimeout(() => ..., delay)` shape is suppressed at the sink
//!   recogniser — the second argument (delay) is never inspected.
//!
//! Slice 1 is single-file, has no sanitiser recognition, and emits no
//! cross-file summaries. The canonical safe fix is to remove the
//! dynamic call entirely (parse the value with `Number` / `parseInt`,
//! or validate with `zod`); future slices may add escalation for
//! `JSON.parse` and `vm.runIn*` wrappers.
//!
//! See `docs/rules/flow-eval-injection.md` for the rule's contract.

use std::collections::HashMap;

use stryx_ast::{
    Visit,
    ast::{
        Argument, ArrowFunctionExpression, AssignmentExpression, AssignmentTarget, BindingPattern,
        CallExpression, ChainElement, Expression, Function, NewExpression, ObjectPropertyKind,
        PropertyKey, VariableDeclarator,
    },
    to_span,
};
use stryx_core::{Finding, Severity};

use crate::adapters::EnabledAdapters;
use crate::flows::unvalidated_body_to_db::decorated_param_names_for_adapters;
use crate::steps::sinks::eval::{is_eval_new_expression, is_eval_sink_call};
use crate::steps::sources::BodySource;
use crate::steps::{StepCtx, StepKind};
use crate::{Rule, RuleContext, RuleMeta};

const RULE_ID: &str = "flow/eval-injection";

// EvalSink is not yet registered on `StepKind` — it lands at rule
// integration time. Until then the rule recognises eval sinks via the
// freestanding `is_eval_sink_call` / `is_eval_new_expression` helpers
// directly, and only the source half of the registry (BodySource) is
// consulted through `StepKind` dispatch. Once registration adds the
// `StepKind::EvalSink` variant, append it here and route sink checks
// through `registry_as_sink` for parity with the other flow rules.
const RULE_STEPS: &[StepKind] = &[StepKind::BodySource(BodySource)];

pub struct EvalInjection;

impl EvalInjection {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EvalInjection {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EvalInjection {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: RULE_ID,
            default_severity: Severity::Critical,
            description: "Untrusted request input reaches a JavaScript dynamic-code call (eval / Function / setTimeout / setInterval with a string payload).",
        }
    }

    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding> {
        let mut visitor =
            EvalInjectionVisitor::new_with_adapters(ctx.file.path.clone(), ctx.index, ctx.adapters);
        for stmt in &ctx.file.program.body {
            visitor.visit_statement(stmt);
        }
        visitor.findings
    }
}

struct EvalInjectionVisitor<'idx> {
    file: std::path::PathBuf,
    scopes: Vec<HashMap<String, ()>>,
    findings: Vec<Finding>,
    /// Read-only project index. Single-file slice does not consult it,
    /// but threading it through keeps the constructor shape aligned
    /// with the canonical `new_with_adapters(path, index, adapters)`
    /// helper so future cross-file extensions don't require a wider
    /// edit.
    index: Option<&'idx stryx_index::ProjectIndex>,
    /// Active stack adapters from the project profile. Consumed by
    /// the body-decorated-param pre-taint pass in `visit_function` so
    /// NestJS `@Body() / @Query() / @Param() / @Headers() / @Req()`
    /// flows light up (and any future framework decorators an adapter
    /// registers).
    adapters: Option<&'idx EnabledAdapters>,
}

impl<'idx> EvalInjectionVisitor<'idx> {
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

    /// Substrate-style sink gate. Currently unused (see comment in
    /// `check_eval_sink`); kept here so rule integration only needs
    /// to add the call back, not re-derive the helper shape.
    #[allow(dead_code)]
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

    fn check_eval_sink(&mut self, call: &CallExpression<'_>) {
        // Sink recognition goes through the freestanding helper, not
        // `registry_as_sink`, because `StepKind::EvalSink` isn't on
        // the closed-enum yet — rule integration adds it. Once added,
        // re-introduce the `registry_as_sink` parity gate.
        if !is_eval_sink_call(call) {
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
                Severity::Critical,
                "Untrusted request input reaches a JavaScript dynamic-code call (eval / Function / setTimeout / setInterval with a string payload). The runtime parses the string as code and executes it under the application's process identity — arbitrary code execution (OWASP A03 / CWE-95).".to_string(),
                to_span(&self.file, call.span),
            )
            .with_help(
                "Remove the dynamic-code call. Parse numeric input with `Number(value)` or `parseInt(value, 10)`; validate structured input with a `zod` schema and reject on failure. For `setTimeout` / `setInterval`, pass a function literal — `setTimeout(() => doWork(value), 1000)` — never a string. The Function constructor and `eval` have no safe variant when the argument is request-controlled.",
            ),
        );
    }

    /// `new Function(<tainted>)` — the constructor form of the dynamic
    /// code sink. Mirrors `check_eval_sink` but for `NewExpression`.
    fn check_eval_new_expression(&mut self, new_expr: &NewExpression<'_>) {
        if !is_eval_new_expression(new_expr) {
            return;
        }
        let Some(first_arg) = new_expr.arguments.first().and_then(argument_expr) else {
            return;
        };
        if !self.expr_taint(first_arg) {
            return;
        }
        self.findings.push(
            Finding::ast(
                RULE_ID,
                Severity::Critical,
                "Untrusted request input reaches `new Function(...)` as the body string. The constructor parses the string as a function body and binds it as a callable — invoking the result executes attacker-controlled code under the application's process identity (OWASP A03 / CWE-95).".to_string(),
                to_span(&self.file, new_expr.span),
            )
            .with_help(
                "Remove the Function constructor. Parse numeric input with `Number(value)` or `parseInt(value, 10)`; validate structured input with a `zod` schema. The Function constructor has no safe variant when its body string is request-controlled.",
            ),
        );
    }
}

impl<'a, 'idx> Visit<'a> for EvalInjectionVisitor<'idx> {
    fn visit_function(&mut self, func: &Function<'a>, _flags: stryx_ast::ScopeFlags) {
        self.enter_fn();
        // NestJS-style decorated param pre-taint. Active set is sourced
        // from `EnabledAdapters` so this rule lights up on every body
        // decorator a stack adapter contributes (NestJS, plus any future
        // adapter that registers a `DecoratedParam` source).
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
        self.check_eval_sink(call);
        stryx_ast::walk::walk_call_expression(self, call);
    }

    fn visit_new_expression(&mut self, new_expr: &NewExpression<'a>) {
        self.check_eval_new_expression(new_expr);
        stryx_ast::walk::walk_new_expression(self, new_expr);
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
