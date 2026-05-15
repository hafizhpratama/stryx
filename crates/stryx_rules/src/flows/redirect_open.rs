//! `flow/redirect-open` — slice 1 (single-file) + slice 2
//! (cross-file via ExportedFunctionSummary).
//!
//! Detects request-body-tainted values reaching a redirect call
//! (`NextResponse.redirect(...)`, bare `redirect(...)` from
//! `next/navigation`, `res.redirect(...)`, `Response.redirect(...)`)
//! as the target URL without a recognised allow-list sanitiser
//! along the path. Structurally identical to
//! [`crate::flows::ssrf_via_fetch`] — same source, same allow-list
//! sanitiser helpers (now shared in `steps::sanitizers::url_allowlist`),
//! different sink set.
//!
//! Slice 2 — cross-file. The route handler hands body data to an
//! imported helper that issues the redirect. The extract pass
//! simulates each exported function with one parameter pre-tainted
//! and records the result on
//! `ParamFlow::reaches_redirect_sink_unsanitized`; the run pass
//! walks call sites in the handler, looks up the callee via the
//! project index, and emits a finding when a tainted argument flows
//! into a reach-flagged parameter slot.
//!
//! See `docs/rules/flow-redirect-open.md` for the rule's contract.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use stryx_ast::{
    Visit,
    ast::{
        Argument, ArrowFunctionExpression, AssignmentExpression, AssignmentTarget, BindingPattern,
        CallExpression, ChainElement, Declaration, ExportDefaultDeclarationKind, Expression,
        Function, FunctionBody, IfStatement, ObjectPropertyKind, Program, PropertyKey, Statement,
        VariableDeclarator,
    },
    to_span,
};
use stryx_core::{Finding, Severity, Span};
use stryx_index::FileSummary;
use stryx_taint::{ExportedFunctionSummary, ParamFlow};

use crate::steps::sanitizers::{
    branch_returns, extract_url_constructor_input, match_url_allow_list_guard,
};
use crate::steps::sinks::{RedirectSink, is_redirect_sink_call};
use crate::steps::sources::BodySource;
use crate::steps::{StepCtx, StepKind};
use crate::{ExtractOutput, Rule, RuleContext, RuleMeta};

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

    fn extract<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> ExtractOutput {
        Some(extract_summary(
            ctx.file.path.clone(),
            &ctx.file.program,
            ctx.index,
        ))
    }

    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding> {
        let mut visitor = RedirectVisitor::new(ctx.file.path.clone(), ctx.index, true);
        for stmt in &ctx.file.program.body {
            visitor.visit_statement(stmt);
        }
        visitor.findings
    }
}

struct RedirectVisitor<'idx> {
    file: PathBuf,
    scopes: Vec<HashMap<String, ()>>,
    /// URL-constructor lineage map — mirrors `SsrfVisitor.url_inits`.
    url_inits: HashMap<String, String>,
    /// Read-only project index. `Some` during the run pass (cross-file
    /// callee lookups go through it); `Some(previous-round)` during
    /// the extract pass simulation so chains converge multi-hop.
    index: Option<&'idx stryx_index::ProjectIndex>,
    /// Honour `body_source_active` at the step level — `true` for
    /// the run pass, `false` during per-param simulation (only the
    /// pre-tainted parameter contributes; ambient `req.body` reads
    /// must not turn into spurious sinks inside helpers that don't
    /// take a request).
    body_source_active: bool,
    findings: Vec<Finding>,
}

impl<'idx> RedirectVisitor<'idx> {
    fn new(
        file: PathBuf,
        index: Option<&'idx stryx_index::ProjectIndex>,
        body_source_active: bool,
    ) -> Self {
        Self {
            file,
            scopes: vec![HashMap::new()],
            url_inits: HashMap::new(),
            index,
            body_source_active,
            findings: Vec::new(),
        }
    }

    fn step_ctx(&self) -> StepCtx<'_, 'idx> {
        StepCtx {
            file: &self.file,
            index: self.index,
            body_source_active: self.body_source_active,
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

    /// Look up the callee through the project index — bare-ident
    /// imports and same-file top-level functions. Returns the
    /// ExportedFunctionSummary whose `params[i].reaches_redirect_sink_unsanitized`
    /// flag tells us whether passing tainted data at position `i`
    /// would reach a redirect sink inside the callee.
    fn lookup_callee_summary(
        &self,
        callee: &Expression<'_>,
    ) -> Option<&'idx ExportedFunctionSummary> {
        let index = self.index?;
        let Expression::Identifier(id) = callee else {
            return None;
        };
        let name = id.name.as_str();
        if let Some(s) = index.resolve_summary(&self.file, name) {
            return Some(s);
        }
        let file = index.file(&self.file)?;
        file.exports.get(name).or_else(|| file.locals.get(name))
    }

    fn check_cross_file_call(&mut self, call: &CallExpression<'_>) {
        let Some(summary) = self.lookup_callee_summary(&call.callee) else {
            return;
        };
        let callee_label = callee_chain(&call.callee).unwrap_or_else(|| "<call>".to_string());
        for (i, arg) in call.arguments.iter().enumerate() {
            let Some(arg_expr) = argument_expr(arg) else {
                continue;
            };
            if !self.expr_taint(arg_expr) {
                continue;
            }
            if !summary.taints_through_redirect_param(i) {
                continue;
            }
            let param_name = summary
                .params
                .get(i)
                .map(|p| p.name.as_str())
                .unwrap_or("?");
            self.findings.push(
                Finding::ast(
                    RULE_ID,
                    Severity::High,
                    format!(
                        "Untrusted request input flows into `{callee_label}` (param `{param_name}`), \
                         which issues a redirect without a recognised allow-list check."
                    ),
                    to_span(&self.file, call.span),
                )
                .with_help(
                    "Validate the URL against an allow-list at this call site, or inside the called helper before the redirect.",
                ),
            );
        }
    }
}

impl<'a, 'idx> Visit<'a> for RedirectVisitor<'idx> {
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
        // Slice 2 — cross-file. During extract-pass simulation
        // `index` may also be set (so chains converge multi-hop);
        // we run the check whenever an index is present.
        if self.index.is_some() {
            self.check_cross_file_call(call);
        }
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

// Allow-list sanitiser helpers (extract_url_constructor_input,
// match_url_allow_list_guard, branch_returns) live in
// `crate::steps::sanitizers::url_allowlist`. Shared with
// `flow/ssrf-via-fetch`.

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

/// Pretty-print a callee expression for finding messages — bare
/// idents only for slice 2 (member-expression callees aren't
/// resolved cross-file yet). Returns `None` for shapes we don't
/// format.
fn callee_chain(expr: &Expression<'_>) -> Option<String> {
    match expr {
        Expression::Identifier(id) => Some(id.name.to_string()),
        _ => None,
    }
}

// ── Extract pass ───────────────────────────────────────────────────────────
//
// Walk top-level decls. For each function-like export, run a per-parameter
// simulation that pre-taints one param and observes whether the
// [`RedirectVisitor`] records a sink finding. Whatever the simulation
// observes lands on `ParamFlow::reaches_redirect_sink_unsanitized`.
// Identical shape to `flow/ssrf-via-fetch::extract_summary` — different
// sink set, same iterative convergence story.

fn extract_summary(
    file: PathBuf,
    program: &Program<'_>,
    index: Option<&stryx_index::ProjectIndex>,
) -> FileSummary {
    let mut summary = FileSummary {
        path: file.clone(),
        ..Default::default()
    };
    for stmt in &program.body {
        match stmt {
            Statement::FunctionDeclaration(func) => {
                let Some(name) = func.id.as_ref().map(|id| id.name.to_string()) else {
                    continue;
                };
                if let Some(s) =
                    simulate_function(&file, &name, &func.params, func.body.as_deref(), index)
                {
                    summary.locals.insert(name, s);
                }
            }
            Statement::VariableDeclaration(var) => {
                for declarator in &var.declarations {
                    let Some(name) = single_binding_name(&declarator.id) else {
                        continue;
                    };
                    let Some(init) = &declarator.init else {
                        continue;
                    };
                    if let Some(s) = simulate_initialiser(&file, &name, init, index) {
                        summary.locals.insert(name, s);
                    }
                }
            }
            Statement::ExportNamedDeclaration(decl) => {
                let Some(declaration) = &decl.declaration else {
                    continue;
                };
                match declaration {
                    Declaration::FunctionDeclaration(func) => {
                        let Some(name) = func.id.as_ref().map(|id| id.name.to_string()) else {
                            continue;
                        };
                        if let Some(s) = simulate_function(
                            &file,
                            &name,
                            &func.params,
                            func.body.as_deref(),
                            index,
                        ) {
                            summary.exports.insert(name, s);
                        }
                    }
                    Declaration::VariableDeclaration(var) => {
                        for declarator in &var.declarations {
                            let Some(name) = single_binding_name(&declarator.id) else {
                                continue;
                            };
                            let Some(init) = &declarator.init else {
                                continue;
                            };
                            if let Some(s) = simulate_initialiser(&file, &name, init, index) {
                                summary.exports.insert(name, s);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Statement::ExportDefaultDeclaration(decl) => match &decl.declaration {
                ExportDefaultDeclarationKind::FunctionDeclaration(func) => {
                    let name = func
                        .id
                        .as_ref()
                        .map(|id| id.name.to_string())
                        .unwrap_or_else(|| "default".to_string());
                    if let Some(s) =
                        simulate_function(&file, &name, &func.params, func.body.as_deref(), index)
                    {
                        summary.exports.insert("default".to_string(), s);
                    }
                }
                ExportDefaultDeclarationKind::ArrowFunctionExpression(arrow) => {
                    let s = simulate_arrow(&file, "default", &arrow.params, &arrow.body, index);
                    summary.exports.insert("default".to_string(), s);
                }
                _ => {}
            },
            _ => {}
        }
    }
    summary
}

fn simulate_initialiser(
    file: &Path,
    name: &str,
    init: &Expression<'_>,
    index: Option<&stryx_index::ProjectIndex>,
) -> Option<ExportedFunctionSummary> {
    match init {
        Expression::FunctionExpression(func) => {
            simulate_function(file, name, &func.params, func.body.as_deref(), index)
        }
        Expression::ArrowFunctionExpression(arrow) => Some(simulate_arrow(
            file,
            name,
            &arrow.params,
            &arrow.body,
            index,
        )),
        _ => None,
    }
}

fn simulate_function(
    file: &Path,
    name: &str,
    params: &stryx_ast::ast::FormalParameters<'_>,
    body: Option<&FunctionBody<'_>>,
    index: Option<&stryx_index::ProjectIndex>,
) -> Option<ExportedFunctionSummary> {
    let body_stmts = body.map(|b| b.statements.as_slice()).unwrap_or(&[]);
    Some(build_summary(file, name, params, body_stmts, index))
}

fn simulate_arrow(
    file: &Path,
    name: &str,
    params: &stryx_ast::ast::FormalParameters<'_>,
    body: &FunctionBody<'_>,
    index: Option<&stryx_index::ProjectIndex>,
) -> ExportedFunctionSummary {
    build_summary(file, name, params, &body.statements, index)
}

fn build_summary(
    file: &Path,
    name: &str,
    params: &stryx_ast::ast::FormalParameters<'_>,
    body: &[Statement<'_>],
    index: Option<&stryx_index::ProjectIndex>,
) -> ExportedFunctionSummary {
    let param_names: Vec<String> = params
        .items
        .iter()
        .map(|p| single_binding_name(&p.pattern).unwrap_or_else(|| format!("_arg{}", p.span.start)))
        .collect();

    let mut params_out = Vec::with_capacity(param_names.len());
    for pname in &param_names {
        let mut visitor = RedirectVisitor::new(file.to_path_buf(), index, false);
        visitor.taint(pname.clone());
        for stmt in body {
            visitor.visit_statement(stmt);
        }
        let reaches = !visitor.findings.is_empty();
        let sink_span = visitor.findings.first().map(|f| f.span.clone());
        params_out.push(ParamFlow {
            name: pname.clone(),
            reaches_redirect_sink_unsanitized: reaches,
            sink_span,
            ..Default::default()
        });
    }

    ExportedFunctionSummary {
        name: name.to_string(),
        params: params_out,
        span: Span::new(file.to_path_buf(), params.span.start, params.span.end),
        contains_auth_check: false,
        validates_request_body: false,
    }
}
