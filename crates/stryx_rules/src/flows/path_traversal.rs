//! `flow/path-traversal` — slice 1 (single-file).
//!
//! Detects request-body-tainted values reaching an `fs.<method>(...)` /
//! `fsPromises.<method>(...)` / `fs.promises.<method>(...)` call as
//! the path argument. Slice 1 is single-file and has no sanitiser
//! recognition — the canonical `path.resolve(base, input)` +
//! `startsWith(base)` defense is a slice-2 candidate.
//!
//! See `docs/rules/flow-path-traversal.md` for the rule's contract.

use std::collections::HashMap;

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
use crate::steps::sinks::{FsSink, is_fs_sink_call};
use crate::steps::sources::BodySource;
use crate::steps::{StepCtx, StepKind};
use crate::{Rule, RuleContext, RuleMeta};

const RULE_ID: &str = "flow/path-traversal";

const RULE_STEPS: &[StepKind] = &[StepKind::BodySource(BodySource), StepKind::FsSink(FsSink)];

pub struct PathTraversal;

impl PathTraversal {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PathTraversal {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PathTraversal {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: RULE_ID,
            default_severity: Severity::High,
            description: "Untrusted request input reaches a filesystem call as the path argument without a path-resolve-then-prefix-check sanitiser.",
        }
    }

    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding> {
        let mut visitor =
            PathTraversalVisitor::new_with_adapters(ctx.file.path.clone(), ctx.index, ctx.adapters);
        for stmt in &ctx.file.program.body {
            visitor.visit_statement(stmt);
        }
        visitor.findings
    }
}

struct PathTraversalVisitor<'idx> {
    file: std::path::PathBuf,
    scopes: Vec<HashMap<String, ()>>,
    findings: Vec<Finding>,
    /// Read-only project index. Slice 1 of this rule is single-file
    /// and the step recognisers it consults (`BodySource`, `FsSink`)
    /// do not read `index` today — but we still thread it through so
    /// the constructor signature matches the canonical
    /// `new_with_adapters(path, index, adapters)` shape shipped in
    /// commit `e422557` for the flagship rule. Future cross-file
    /// extensions can drop in here without resurrecting a wider edit.
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

impl<'idx> PathTraversalVisitor<'idx> {
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

    fn check_fs_sink(&mut self, call: &CallExpression<'_>) {
        if !is_fs_sink_call(call) || !self.registry_as_sink(call) {
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
                "Untrusted request input reaches a filesystem call as the path argument without a recognised allow-list or path-confinement check.".to_string(),
                to_span(&self.file, call.span),
            )
            .with_help(
                "Resolve the path with `path.resolve(base, input)` and check the result starts with `base + path.sep` before opening it. Reject anything outside the allow-listed directory with a 4xx response.",
            ),
        );
    }
}

impl<'a, 'idx> Visit<'a> for PathTraversalVisitor<'idx> {
    fn visit_function(&mut self, func: &Function<'a>, _flags: stryx_ast::ScopeFlags) {
        self.enter_fn();
        // NestJS and similar frameworks declare body sources via parameter
        // decorators (`@Body() dto: CreateUserDto`). Pre-taint any param
        // marked with a decorator the active adapter set recognises — the
        // framework will inject body data there. Without any adapter
        // (legacy test sites that build a visitor directly), only `@Body()`
        // is recognised, preserving prior behaviour for existing fixtures.
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
        self.check_fs_sink(call);
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

// Decorator pre-taint helpers are shared from the flagship rule
// (`flows/unvalidated_body_to_db::decorated_param_names_for_adapters`)
// via `pub(crate)`. Single source of truth for the DTO-suffix heuristic,
// active-decorator union, and decorator-shape matching — so any future
// substrate tweak (new `AstMatcher::DecoratedParam` consumers, looser
// validated-DTO rules) lands in one place and every body-source flow
// rule picks it up.
