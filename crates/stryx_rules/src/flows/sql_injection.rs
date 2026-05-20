//! `flow/sql-injection` — slice 1 (single-file) + slice 2
//! (cross-file via ExportedFunctionSummary).
//!
//! Detects request-body-tainted values reaching a raw-SQL sink —
//! Prisma's `$queryRawUnsafe` / `$executeRawUnsafe`, Drizzle's
//! `sql.raw`, or node-postgres / mysql2 `<conn>.query(<sql>, ...)`
//! where `<conn>` is `pool` / `client` / `db` / `connection`.
//!
//! The parameterised tagged-template forms (`prisma.$queryRaw\`...\``,
//! Drizzle's `sql\`...\``) are deliberately *not* sinks here — they
//! generate parameterised SQL and are safe by construction. The
//! recogniser only matches the call-expression escape-hatch shapes.
//!
//! Slice 2 — cross-file. The route handler hands body data to an
//! imported helper that does the raw-SQL call. The extract pass
//! simulates each exported function with one parameter pre-tainted
//! and records the result on
//! `ParamFlow::reaches_sql_sink_unsanitized`; the run pass walks
//! call sites in the handler, looks up the callee via the project
//! index, and emits a finding when a tainted argument flows into a
//! reach-flagged parameter slot.
//!
//! See `docs/rules/flow-sql-injection.md` for the rule's contract
//! and the bad/good fixtures it pins.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use stryx_ast::{
    Visit,
    ast::{
        Argument, ArrowFunctionExpression, AssignmentExpression, AssignmentTarget, BindingPattern,
        CallExpression, ChainElement, Declaration, ExportDefaultDeclarationKind, Expression,
        Function, FunctionBody, ObjectPropertyKind, Program, PropertyKey, Statement,
        VariableDeclarator,
    },
    to_span,
};
use stryx_core::{Finding, Severity, Span};
use stryx_index::FileSummary;
use stryx_taint::{ExportedFunctionSummary, ParamFlow};

use crate::adapters::EnabledAdapters;
use crate::flows::unvalidated_body_to_db::decorated_param_names_for_adapters;
use crate::steps::sinks::{SqlSink, is_sql_sink_call};
use crate::steps::sources::BodySource;
use crate::steps::{StepCtx, StepKind};
use crate::{ExtractOutput, Rule, RuleContext, RuleMeta};

const RULE_ID: &str = "flow/sql-injection";

const RULE_STEPS: &[StepKind] = &[StepKind::BodySource(BodySource), StepKind::SqlSink(SqlSink)];

pub struct SqlInjection;

impl SqlInjection {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SqlInjection {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SqlInjection {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: RULE_ID,
            default_severity: Severity::Critical,
            description: "Untrusted request input reaches a raw-SQL sink (Prisma $queryRawUnsafe, Drizzle sql.raw, node-postgres/mysql2 .query) without parameterisation.",
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
        let mut visitor = SqlInjectionVisitor::new_with_adapters(
            ctx.file.path.clone(),
            ctx.index,
            true,
            ctx.adapters,
        );
        for stmt in &ctx.file.program.body {
            visitor.visit_statement(stmt);
        }
        visitor.findings
    }
}

struct SqlInjectionVisitor<'idx> {
    file: PathBuf,
    /// Stack of per-function scopes. Each scope maps binding name to `()`
    /// when that binding holds body-tainted data.
    scopes: Vec<HashMap<String, ()>>,
    /// Read-only project index. `Some` during the run pass; `None`
    /// during per-param simulation.
    index: Option<&'idx stryx_index::ProjectIndex>,
    /// Honour `body_source_active` at the step level — true on the run
    /// pass (body sources fire naturally), false during per-param
    /// simulation (only the pre-tainted param contributes; ambient
    /// `req.body` reads inside helpers must not spawn spurious sinks).
    body_source_active: bool,
    /// Active stack adapters resolved from the project's
    /// `ProjectProfile`. `None` when the rule is exercised outside the
    /// production scan loop (unit-test sites that build a visitor
    /// directly, or the per-param simulation that runs during summary
    /// extraction). Consumed by the decorator pre-taint pass in
    /// `visit_function` to extend `@Body()`-only recognition to every
    /// `DecoratedParam` source pattern an active adapter contributes
    /// (`@Query()` / `@Param()` / `@Headers()` / `@Req()` for the
    /// NestJS adapter, future framework decorators too).
    adapters: Option<&'idx EnabledAdapters>,
    findings: Vec<Finding>,
}

impl<'idx> SqlInjectionVisitor<'idx> {
    fn new(
        file: PathBuf,
        index: Option<&'idx stryx_index::ProjectIndex>,
        body_source_active: bool,
    ) -> Self {
        Self::new_with_adapters(file, index, body_source_active, None)
    }

    fn new_with_adapters(
        file: PathBuf,
        index: Option<&'idx stryx_index::ProjectIndex>,
        body_source_active: bool,
        adapters: Option<&'idx EnabledAdapters>,
    ) -> Self {
        Self {
            file,
            scopes: vec![HashMap::new()],
            index,
            body_source_active,
            adapters,
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
            // Assignment-as-expression — `(q = body)` evaluates to the
            // RHS. Propagates taint for shapes like `foo(q = body)` and
            // `q = (r = body)`. The mutation lives in
            // `visit_assignment_expression`.
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

    fn check_sql_sink(&mut self, call: &CallExpression<'_>) {
        if !is_sql_sink_call(call) || !self.registry_as_sink(call) {
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
                "Untrusted request input reaches a raw-SQL call as the query string without parameterisation. The attacker can splice arbitrary SQL into the parsed statement (OWASP A03 / CWE-89).".to_string(),
                to_span(&self.file, call.span),
            )
            .with_help(
                "Switch to the parameterised path. Prisma: use `prisma.$queryRaw`...`` (tagged template) instead of `$queryRawUnsafe`. Drizzle: use the `sql`...`` tagged template instead of `sql.raw`. node-postgres / mysql2: pass values as the second-argument bind array (`pool.query('SELECT ... WHERE id = $1', [id])`). If a dynamic identifier is genuinely required, allow-list it against a hardcoded set before splicing.",
            ),
        );
    }

    /// Look up the callee through the project index — bare-ident
    /// imports and same-file top-level functions. Returns the
    /// ExportedFunctionSummary whose `params[i].reaches_sql_sink_unsanitized`
    /// flag tells us whether passing tainted data at position `i`
    /// would reach a raw-SQL sink inside the callee.
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

    /// Cross-file consumer — when a tainted argument is passed at a
    /// call site whose callee summary records
    /// `reaches_sql_sink_unsanitized` at that argument position,
    /// emit a Critical-severity finding at the call site.
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
            if !summary.taints_through_sql_param(i) {
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
                    Severity::Critical,
                    format!(
                        "Untrusted request input flows into `{callee_label}` (param `{param_name}`), which splices into a raw-SQL call inside the helper without parameterisation (OWASP A03 / CWE-89)."
                    ),
                    to_span(&self.file, call.span),
                )
                .with_help(
                    "Switch the helper to the parameterised path (Prisma tagged `$queryRaw`, Drizzle `sql`...``, or node-postgres `query(text, [bind])`), or validate the value against a hardcoded allow-list before splicing.",
                ),
            );
        }
    }
}

impl<'a, 'idx> Visit<'a> for SqlInjectionVisitor<'idx> {
    fn visit_function(&mut self, func: &Function<'a>, _flags: stryx_ast::ScopeFlags) {
        self.enter_fn();
        // NestJS and similar frameworks declare body sources via parameter
        // decorators (`@Body() dto: CreateUserDto`). Pre-taint any param
        // marked with one — the framework will inject body data there.
        //
        // The set of recognised decorators is contributed by the active
        // `EnabledAdapters` (NestJS adapter → `@Body() / @Query() /
        // @Param() / @Headers() / @Req()`). When no adapter is wired
        // (per-param simulation, unit-test paths), the helper falls
        // back to `@Body()`-only recognition, preserving byte-identical
        // behaviour for existing fixtures.
        //
        // Helper imported from the flagship rule
        // (`flows::unvalidated_body_to_db::decorated_param_names_for_adapters`)
        // rather than duplicated — it has no private dependencies that
        // would force inline copying, and a single owner keeps the
        // decorator-recognition logic consistent across all body-source
        // rules during the v0.4.0 migration.
        if self.body_source_active {
            for pname in decorated_param_names_for_adapters(&func.params, self.adapters) {
                self.taint(pname);
            }
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
        self.check_sql_sink(call);
        // Slice 2 — cross-file: index-bearing run pass only.
        if self.index.is_some() {
            self.check_cross_file_call(call);
        }
        stryx_ast::walk::walk_call_expression(self, call);
    }

    fn visit_assignment_expression(&mut self, a: &AssignmentExpression<'a>) {
        // Bare reassignment `q = ...` updates the binding's taint state.
        // A tainted RHS taints the LHS binding; a clean RHS clears prior
        // taint (mirrors the flagship rule's behaviour).
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

fn single_binding_name(pat: &BindingPattern<'_>) -> Option<String> {
    if let BindingPattern::BindingIdentifier(id) = pat {
        Some(id.name.to_string())
    } else {
        None
    }
}

/// Pretty-print a callee expression for finding messages — bare
/// idents only (member-expression callees aren't resolved cross-file
/// yet). Returns `None` for shapes we don't format.
fn callee_chain(expr: &Expression<'_>) -> Option<String> {
    match expr {
        Expression::Identifier(id) => Some(id.name.to_string()),
        _ => None,
    }
}

// ── Extract pass ───────────────────────────────────────────────────────────
//
// Walk top-level decls. For each function-like export (FunctionDeclaration,
// `const x = (...)=>{}`, default-exported function/arrow), run a
// per-parameter simulation that pre-taints one param and observes whether
// the [`SqlInjectionVisitor`] records a sink finding. Whatever the
// simulation observes lands on `ParamFlow::reaches_sql_sink_unsanitized`.
//
// Slice 2 deliberately does *not* populate `param_shape`, `return_shape`,
// `tainted_offsets`, `propagates_to_return`, or class methods — those are
// the db rule's territory (and merge_per_rule_flags keeps db's richer
// fields on collision). Slice 2's contribution is reach-only.

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
                    if let Some(s) = simulate_function(
                        &file,
                        "default",
                        &func.params,
                        func.body.as_deref(),
                        index,
                    ) {
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
        // One param pre-tainted, body-source recognition disabled.
        // The visitor sees the previous round's index so already-known
        // sink calls inside this callee contribute — chains converge
        // through multi-level helpers (route → service → dao).
        let mut visitor = SqlInjectionVisitor::new(file.to_path_buf(), index, false);
        visitor.taint(pname.clone());
        for stmt in body {
            visitor.visit_statement(stmt);
        }
        let reaches = !visitor.findings.is_empty();
        let sink_span = visitor.findings.first().map(|f| f.span.clone());
        params_out.push(ParamFlow {
            name: pname.clone(),
            reaches_sql_sink_unsanitized: reaches,
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
