//! `flow/unvalidated-body-to-db` — slice 1 + slice 2.
//!
//! Detects request-body data flowing into a DB write call (Prisma, generic
//! `db.X.create/update/upsert`) without passing through a parser-style
//! sanitizer (`Schema.parse(...)`, `Schema.safeParse(...)`).
//!
//! - **Slice 1** (intra-procedural): within a function body, any local
//!   variable initialised from a request-body source is tracked, and a
//!   finding fires if it reaches a DB sink without being sanitised first.
//! - **Slice 2** (cross-file): during the engine's extract pass, every
//!   exported function gets a per-parameter summary stating whether
//!   that parameter — if tainted — would reach a DB sink. The run pass
//!   consults `ProjectIndex::resolve_summary` at every call site to
//!   detect cross-file flows: `route.ts` calls `createUser(body)` and
//!   `lib.ts`'s `createUser` writes to the DB without validation.

use std::collections::HashSet;
use std::path::PathBuf;

use stryx_ast::{
    ast::{
        ArrowFunctionExpression, BindingPattern, CallExpression, Declaration,
        ExportDefaultDeclarationKind, ExportNamedDeclaration, Expression, Function,
        FunctionBody, ImportDeclaration, ImportDeclarationSpecifier,
        ImportOrExportKind, MemberExpression, ObjectPropertyKind,
        Program, PropertyKey, Statement, VariableDeclaration,
    },
    to_span, ScopeFlags, Visit,
};
use stryx_core::{Finding, Severity, Span};
use stryx_index::{FileSummary, ImportRef};
use stryx_taint::{ExportedFunctionSummary, ParamFlow};

use crate::{ExtractOutput, Rule, RuleContext, RuleMeta};

const RULE_ID: &str = "flow/unvalidated-body-to-db";

pub struct UnvalidatedBodyToDb;

impl UnvalidatedBodyToDb {
    pub fn new() -> Self {
        Self
    }
}

impl Default for UnvalidatedBodyToDb {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnvalidatedBodyToDb {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: RULE_ID,
            default_severity: Severity::High,
            description: "Untrusted request body reaches a database write without a validating parser along the path.",
        }
    }

    fn extract<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> ExtractOutput {
        Some(extract_summary(ctx.file.path.clone(), &ctx.file.program))
    }

    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding> {
        let mut visitor = FlowVisitor::new(ctx.file.path.clone(), ctx.index);
        visitor.visit_program(&ctx.file.program);
        visitor.findings
    }
}

struct FlowVisitor<'idx> {
    file: PathBuf,
    findings: Vec<Finding>,
    /// Stack of per-function scopes. Each frame holds the names of local
    /// identifiers currently carrying request-body taint.
    scopes: Vec<HashSet<String>>,
    /// Read-only project index; `Some` during the run pass, `None`
    /// during summary extraction.
    index: Option<&'idx stryx_index::ProjectIndex>,
}

impl<'idx> FlowVisitor<'idx> {
    fn new(file: PathBuf, index: Option<&'idx stryx_index::ProjectIndex>) -> Self {
        Self {
            file,
            findings: Vec::new(),
            scopes: Vec::new(),
            index,
        }
    }

    fn enter_fn(&mut self) {
        self.scopes.push(HashSet::new());
    }

    fn exit_fn(&mut self) {
        self.scopes.pop();
    }

    fn current_scope_mut(&mut self) -> Option<&mut HashSet<String>> {
        self.scopes.last_mut()
    }

    fn is_tainted(&self, name: &str) -> bool {
        self.scopes
            .iter()
            .rev()
            .any(|scope| scope.contains(name))
    }

    fn taint(&mut self, name: String) {
        if let Some(scope) = self.current_scope_mut() {
            scope.insert(name);
        }
    }

    fn handle_function_body(&mut self, body: &[Statement<'_>]) {
        for stmt in body {
            self.handle_statement(stmt);
        }
    }

    fn handle_statement(&mut self, stmt: &Statement<'_>) {
        match stmt {
            Statement::VariableDeclaration(decl) => self.handle_var_decl(decl),
            Statement::ExpressionStatement(es) => {
                let _ = self.expr_taint(&es.expression);
                self.scan_for_sinks(&es.expression);
            }
            Statement::ReturnStatement(rs) => {
                if let Some(arg) = &rs.argument {
                    let _ = self.expr_taint(arg);
                    self.scan_for_sinks(arg);
                }
            }
            Statement::BlockStatement(bs) => {
                for s in &bs.body {
                    self.handle_statement(s);
                }
            }
            Statement::IfStatement(is) => {
                let _ = self.expr_taint(&is.test);
                self.handle_statement(&is.consequent);
                if let Some(alt) = &is.alternate {
                    self.handle_statement(alt);
                }
            }
            Statement::TryStatement(ts) => {
                for s in &ts.block.body {
                    self.handle_statement(s);
                }
                if let Some(handler) = &ts.handler {
                    for s in &handler.body.body {
                        self.handle_statement(s);
                    }
                }
                if let Some(finalizer) = &ts.finalizer {
                    for s in &finalizer.body {
                        self.handle_statement(s);
                    }
                }
            }
            // Functions/classes inside a function body open new scopes; the
            // outer Visit handlers below take care of those when reached
            // through the AST walk. Other statement kinds don't propagate
            // taint in slice 1 — a deliberately small surface.
            other => {
                // Fall back to the default visit for anything we don't
                // explicitly handle so sinks inside switch/for/while still
                // get scanned.
                self.visit_statement(other);
            }
        }
    }

    fn handle_var_decl(&mut self, decl: &VariableDeclaration<'_>) {
        for declarator in &decl.declarations {
            let Some(init) = &declarator.init else { continue };
            let tainted = self.expr_taint(init);
            self.scan_for_sinks(init);
            if !tainted {
                continue;
            }
            // For destructuring patterns like `const { name } = body`, taint
            // every introduced binding. For a plain identifier, taint just it.
            for name in collect_binding_names(&declarator.id) {
                self.taint(name);
            }
        }
    }

    /// Returns true if this expression's *value* should be considered
    /// body-tainted.
    fn expr_taint(&mut self, expr: &Expression<'_>) -> bool {
        match expr {
            Expression::Identifier(id) => self.is_tainted(id.name.as_str()),

            Expression::AwaitExpression(aw) => self.expr_taint(&aw.argument),

            Expression::ParenthesizedExpression(p) => self.expr_taint(&p.expression),

            Expression::CallExpression(call) => {
                // A sanitizer call clears taint regardless of its argument.
                if is_sanitizer_call(call) {
                    // Still walk arguments to record any nested sinks/taint.
                    for arg in &call.arguments {
                        if let Some(e) = arg.as_expression() {
                            let _ = self.expr_taint(e);
                            self.scan_for_sinks(e);
                        }
                    }
                    return false;
                }
                // A DB-read call (findUnique/findFirst/findMany/count etc.)
                // returns a Prisma-typed row, not body data. Taint in its
                // where-clause does not propagate into the returned value.
                // Walk args to record nested taint/sinks but report the
                // result as clean.
                if is_db_read_call(call) {
                    for arg in &call.arguments {
                        if let Some(e) = arg.as_expression() {
                            let _ = self.expr_taint(e);
                            self.scan_for_sinks(e);
                        }
                    }
                    return false;
                }
                // A request-body source call returns tainted data.
                if is_body_source_call(call) {
                    return true;
                }
                // For any other call, taint propagates if any argument is
                // tainted (conservative; refinements come with summaries).
                let mut any_tainted = false;
                for arg in &call.arguments {
                    if let Some(e) = arg.as_expression()
                        && self.expr_taint(e)
                    {
                        any_tainted = true;
                    }
                }
                self.scan_for_sinks(&call.callee);
                any_tainted
            }

            Expression::StaticMemberExpression(m) => {
                // `req.body` / `request.body` are body sources.
                if is_request_body_member(&m.object, m.property.name.as_str()) {
                    return true;
                }
                self.expr_taint(&m.object)
            }

            Expression::ComputedMemberExpression(m) => self.expr_taint(&m.object),
            Expression::PrivateFieldExpression(m) => self.expr_taint(&m.object),

            Expression::ObjectExpression(obj) => {
                let mut tainted = false;
                for prop in &obj.properties {
                    match prop {
                        ObjectPropertyKind::ObjectProperty(p) => {
                            if self.expr_taint(&p.value) {
                                tainted = true;
                            }
                        }
                        ObjectPropertyKind::SpreadProperty(s) => {
                            if self.expr_taint(&s.argument) {
                                tainted = true;
                            }
                        }
                    }
                }
                tainted
            }

            Expression::ArrayExpression(arr) => {
                let mut tainted = false;
                for el in &arr.elements {
                    if let Some(e) = el.as_expression()
                        && self.expr_taint(e)
                    {
                        tainted = true;
                    }
                }
                tainted
            }

            Expression::TemplateLiteral(t) => {
                let mut tainted = false;
                for e in &t.expressions {
                    if self.expr_taint(e) {
                        tainted = true;
                    }
                }
                tainted
            }

            Expression::ConditionalExpression(c) => {
                let _ = self.expr_taint(&c.test);
                let l = self.expr_taint(&c.consequent);
                let r = self.expr_taint(&c.alternate);
                l || r
            }

            Expression::LogicalExpression(b) => {
                let l = self.expr_taint(&b.left);
                let r = self.expr_taint(&b.right);
                l || r
            }

            Expression::BinaryExpression(b) => {
                let l = self.expr_taint(&b.left);
                let r = self.expr_taint(&b.right);
                l || r
            }

            Expression::AssignmentExpression(a) => {
                let r = self.expr_taint(&a.right);
                if r
                    && let Some(name) = assignment_target_name(&a.left)
                {
                    self.taint(name);
                }
                r
            }

            Expression::TSAsExpression(t) => self.expr_taint(&t.expression),
            Expression::TSNonNullExpression(t) => self.expr_taint(&t.expression),
            Expression::TSSatisfiesExpression(t) => self.expr_taint(&t.expression),
            Expression::TSTypeAssertion(t) => self.expr_taint(&t.expression),

            _ => false,
        }
    }

    /// Walks an expression tree purely to find DB sink call sites and report
    /// findings on tainted arguments. Doesn't update taint state.
    fn scan_for_sinks(&mut self, expr: &Expression<'_>) {
        match expr {
            Expression::CallExpression(call) => {
                // Slice 2: cross-file sink — a call to an imported
                // function whose summary marks the receiving param as
                // sinking to the DB without sanitisation.
                self.check_cross_file_call(call);

                if is_db_write_sink(call) {
                    let any_tainted = call.arguments.iter().any(|arg| {
                        arg.as_expression()
                            .map(|e| self.expr_is_tainted_readonly(e))
                            .unwrap_or(false)
                    });
                    if any_tainted {
                        self.findings.push(
                            Finding::ast(
                                RULE_ID,
                                Severity::High,
                                format!(
                                    "Untrusted request body reaches `{}` without a validating parser along the path.",
                                    callee_chain(&call.callee).unwrap_or_else(|| "db sink".into())
                                ),
                                to_span(&self.file, call.span),
                            )
                            .with_help(
                                "Validate the body with zod/valibot/yup before passing it to the DB write.",
                            ),
                        );
                    }
                }
                // Recurse into callee + args to catch nested sinks.
                self.scan_for_sinks(&call.callee);
                for arg in &call.arguments {
                    if let Some(e) = arg.as_expression() {
                        self.scan_for_sinks(e);
                    }
                }
            }
            Expression::AwaitExpression(a) => self.scan_for_sinks(&a.argument),
            Expression::ParenthesizedExpression(p) => self.scan_for_sinks(&p.expression),
            Expression::StaticMemberExpression(m) => self.scan_for_sinks(&m.object),
            Expression::ComputedMemberExpression(m) => {
                self.scan_for_sinks(&m.object);
                self.scan_for_sinks(&m.expression);
            }
            Expression::ObjectExpression(obj) => {
                for prop in &obj.properties {
                    match prop {
                        ObjectPropertyKind::ObjectProperty(p) => self.scan_for_sinks(&p.value),
                        ObjectPropertyKind::SpreadProperty(s) => self.scan_for_sinks(&s.argument),
                    }
                }
            }
            Expression::ArrayExpression(arr) => {
                for el in &arr.elements {
                    if let Some(e) = el.as_expression() {
                        self.scan_for_sinks(e);
                    }
                }
            }
            _ => {}
        }
    }

    /// Like `expr_taint` but doesn't mutate state — used during sink-arg
    /// inspection where we just need to ask "is this value tainted?".
    fn expr_is_tainted_readonly(&self, expr: &Expression<'_>) -> bool {
        match expr {
            Expression::Identifier(id) => self.is_tainted(id.name.as_str()),
            Expression::AwaitExpression(a) => self.expr_is_tainted_readonly(&a.argument),
            Expression::ParenthesizedExpression(p) => self.expr_is_tainted_readonly(&p.expression),
            Expression::StaticMemberExpression(m) => {
                if is_request_body_member(&m.object, m.property.name.as_str()) {
                    return true;
                }
                self.expr_is_tainted_readonly(&m.object)
            }
            Expression::ComputedMemberExpression(m) => self.expr_is_tainted_readonly(&m.object),
            Expression::CallExpression(call) => {
                if is_sanitizer_call(call) || is_db_read_call(call) {
                    return false;
                }
                if is_body_source_call(call) {
                    return true;
                }
                call.arguments.iter().any(|arg| {
                    arg.as_expression()
                        .map(|e| self.expr_is_tainted_readonly(e))
                        .unwrap_or(false)
                })
            }
            Expression::ObjectExpression(obj) => obj.properties.iter().any(|p| match p {
                ObjectPropertyKind::ObjectProperty(p) => self.expr_is_tainted_readonly(&p.value),
                ObjectPropertyKind::SpreadProperty(s) => self.expr_is_tainted_readonly(&s.argument),
            }),
            Expression::ArrayExpression(arr) => arr.elements.iter().any(|el| {
                el.as_expression()
                    .map(|e| self.expr_is_tainted_readonly(e))
                    .unwrap_or(false)
            }),
            Expression::TemplateLiteral(t) => {
                t.expressions.iter().any(|e| self.expr_is_tainted_readonly(e))
            }
            Expression::ConditionalExpression(c) => {
                self.expr_is_tainted_readonly(&c.consequent)
                    || self.expr_is_tainted_readonly(&c.alternate)
            }
            Expression::LogicalExpression(b) => {
                self.expr_is_tainted_readonly(&b.left)
                    || self.expr_is_tainted_readonly(&b.right)
            }
            Expression::TSAsExpression(t) => self.expr_is_tainted_readonly(&t.expression),
            Expression::TSNonNullExpression(t) => self.expr_is_tainted_readonly(&t.expression),
            Expression::TSSatisfiesExpression(t) => self.expr_is_tainted_readonly(&t.expression),
            Expression::TSTypeAssertion(t) => self.expr_is_tainted_readonly(&t.expression),
            _ => false,
        }
    }
}

impl<'a, 'idx> Visit<'a> for FlowVisitor<'idx> {
    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        self.enter_fn();
        if let Some(body) = &func.body {
            self.handle_function_body(&body.statements);
        }
        self.exit_fn();
        let _ = flags;
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        self.enter_fn();
        // Arrow body is always a FunctionBody; its `statements` contains the
        // expression-bodied case wrapped as a single ExpressionStatement.
        self.handle_function_body(&arrow.body.statements);
        self.exit_fn();
    }
}

impl FlowVisitor<'_> {
    /// Slice 2: when a tainted argument is passed to a call site whose
    /// callee resolves through the project index to a function that
    /// taints that parameter to a sink, emit a cross-file finding.
    fn check_cross_file_call(&mut self, call: &CallExpression<'_>) {
        let Some(index) = self.index else { return };
        let Expression::Identifier(callee_id) = &call.callee else {
            return;
        };
        let Some(summary) = index.resolve_summary(&self.file, callee_id.name.as_str()) else {
            return;
        };
        for (i, arg) in call.arguments.iter().enumerate() {
            let Some(arg_expr) = arg.as_expression() else {
                continue;
            };
            if !self.expr_is_tainted_readonly(arg_expr) {
                continue;
            }
            if !summary.taints_through_param(i) {
                continue;
            }
            let sink_hint = summary
                .params
                .get(i)
                .and_then(|p| p.sink_span.as_ref())
                .map(|s| {
                    format!(
                        " The sink lives in {}.",
                        s.file.display(),
                    )
                })
                .unwrap_or_default();
            self.findings.push(
                Finding::ast(
                    RULE_ID,
                    Severity::High,
                    format!(
                        "Untrusted request body flows into `{}` (param `{}`), which writes to the database without validating it.{sink_hint}",
                        callee_id.name,
                        summary.params.get(i).map(|p| p.name.as_str()).unwrap_or("?"),
                    ),
                    to_span(&self.file, call.span),
                )
                .with_help(
                    "Validate the body with zod/valibot/yup at this call site, or inside the called function before the DB write.",
                ),
            );
        }
    }
}

// ── Pattern matchers ──────────────────────────────────────────────────────

fn is_request_body_member(object: &Expression<'_>, prop: &str) -> bool {
    if prop != "body" {
        return false;
    }
    is_request_like_expr(object)
}

fn is_body_source_call(call: &CallExpression<'_>) -> bool {
    // Forms recognised:
    //   req.json()        request.json()         req.text()       req.formData()
    //   c.req.json()      ctx.req.json()         c.request.json() ctx.request.json()
    //   The Hono variants chain through a context object (`c` or `ctx`).
    let Some(callee) = call.callee.as_member_expression() else {
        return false;
    };
    let MemberExpression::StaticMemberExpression(method_member) = callee else {
        return false;
    };
    if !matches!(
        method_member.property.name.as_str(),
        "json" | "text" | "formData" | "arrayBuffer" | "blob"
    ) {
        return false;
    }
    is_request_like_expr(&method_member.object)
}

/// Matches an expression that we treat as a request object: either a bare
/// `req`/`request`/`ctx`/`c` identifier, or a Hono-style `c.req`/`ctx.request`
/// chain.
fn is_request_like_expr(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::Identifier(id) => {
            matches!(id.name.as_str(), "req" | "request" | "ctx" | "c")
        }
        Expression::StaticMemberExpression(m) => {
            if !matches!(m.property.name.as_str(), "req" | "request") {
                return false;
            }
            matches!(
                &m.object,
                Expression::Identifier(id) if matches!(id.name.as_str(), "ctx" | "c")
            )
        }
        _ => false,
    }
}

fn is_sanitizer_call(call: &CallExpression<'_>) -> bool {
    // Recognised sanitizer methods: parse, safeParse, parseAsync, safeParseAsync.
    // Any object can host them — covers Schema.parse, z.object({}).parse,
    // CreateUserSchema.safeParse, etc.
    let Some(callee) = call.callee.as_member_expression() else {
        return false;
    };
    let prop_name = match callee {
        MemberExpression::StaticMemberExpression(m) => m.property.name.as_str(),
        _ => return false,
    };
    matches!(
        prop_name,
        "parse" | "safeParse" | "parseAsync" | "safeParseAsync"
    )
}

fn is_db_read_call(call: &CallExpression<'_>) -> bool {
    // Prisma read methods on a `prisma.<model>` chain. The result is
    // a typed DB row; we treat it as clean even when the where-clause
    // carries taint.
    const READ_METHODS: &[&str] = &[
        "findUnique",
        "findUniqueOrThrow",
        "findFirst",
        "findFirstOrThrow",
        "findMany",
        "count",
        "aggregate",
        "groupBy",
        "exists",
    ];
    let Some(callee) = call.callee.as_member_expression() else {
        return false;
    };
    let MemberExpression::StaticMemberExpression(method) = callee else {
        return false;
    };
    if !READ_METHODS.contains(&method.property.name.as_str()) {
        return false;
    }
    let Expression::StaticMemberExpression(model_member) = &method.object else {
        return false;
    };
    let Expression::Identifier(root_id) = &model_member.object else {
        return false;
    };
    matches!(root_id.name.as_str(), "prisma" | "db" | "database")
}

fn is_db_write_sink(call: &CallExpression<'_>) -> bool {
    // Recognised DB write methods on Prisma-shaped clients:
    //   prisma.<model>.create / createMany / update / updateMany / upsert /
    //   delete / deleteMany / createManyAndReturn
    // Also accepts a `db.` or `database.` prefix for generic clients.
    const SINK_METHODS: &[&str] = &[
        "create",
        "createMany",
        "createManyAndReturn",
        "update",
        "updateMany",
        "upsert",
        "delete",
        "deleteMany",
    ];

    let Some(callee) = call.callee.as_member_expression() else {
        return false;
    };
    let MemberExpression::StaticMemberExpression(method) = callee else {
        return false;
    };
    if !SINK_METHODS.contains(&method.property.name.as_str()) {
        return false;
    }
    // method.object should be `<root>.<model>` where root ∈ {prisma, db, database}.
    let Expression::StaticMemberExpression(model_member) = &method.object else {
        return false;
    };
    let Expression::Identifier(root_id) = &model_member.object else {
        return false;
    };
    matches!(root_id.name.as_str(), "prisma" | "db" | "database")
}

fn callee_chain(expr: &Expression<'_>) -> Option<String> {
    match expr {
        Expression::Identifier(id) => Some(id.name.to_string()),
        Expression::StaticMemberExpression(m) => {
            let lhs = callee_chain(&m.object)?;
            Some(format!("{lhs}.{}", m.property.name))
        }
        _ => None,
    }
}

fn assignment_target_name(target: &stryx_ast::ast::AssignmentTarget<'_>) -> Option<String> {
    use stryx_ast::ast::{AssignmentTarget, SimpleAssignmentTarget};
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(id) => Some(id.name.to_string()),
        AssignmentTarget::ArrayAssignmentTarget(_)
        | AssignmentTarget::ObjectAssignmentTarget(_) => None,
        _ => match target.as_simple_assignment_target() {
            Some(SimpleAssignmentTarget::AssignmentTargetIdentifier(id)) => {
                Some(id.name.to_string())
            }
            _ => None,
        },
    }
}

fn collect_binding_names(pat: &BindingPattern<'_>) -> Vec<String> {
    let mut out = Vec::new();
    walk_binding_pattern(pat, &mut out);
    out
}

// ── Slice 2: per-file summary extraction ────────────────────────────────

fn extract_summary(file: PathBuf, program: &Program<'_>) -> FileSummary {
    let mut summary = FileSummary {
        path: file.clone(),
        ..Default::default()
    };

    for stmt in &program.body {
        match stmt {
            Statement::ImportDeclaration(decl) => {
                collect_imports(decl, &mut summary);
            }
            Statement::ExportNamedDeclaration(decl) => {
                collect_named_exports(&file, decl, &mut summary);
            }
            Statement::ExportDefaultDeclaration(decl) => {
                collect_default_export(&file, &decl.declaration, &mut summary);
            }
            _ => {}
        }
    }

    summary
}

fn collect_imports(decl: &ImportDeclaration<'_>, summary: &mut FileSummary) {
    // Skip `import type { ... }` — pure types can't carry runtime taint.
    if matches!(decl.import_kind, ImportOrExportKind::Type) {
        return;
    }
    let Some(specifiers) = decl.specifiers.as_ref() else {
        return;
    };
    let module = decl.source.value.to_string();
    for spec in specifiers {
        match spec {
            ImportDeclarationSpecifier::ImportSpecifier(s) => {
                summary.imports.insert(
                    s.local.name.to_string(),
                    ImportRef {
                        module_specifier: module.clone(),
                        imported_name: s.imported.name().to_string(),
                    },
                );
            }
            ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                summary.imports.insert(
                    s.local.name.to_string(),
                    ImportRef {
                        module_specifier: module.clone(),
                        imported_name: "default".to_string(),
                    },
                );
            }
            ImportDeclarationSpecifier::ImportNamespaceSpecifier(_) => {
                // `import * as ns from "..."` — slice 2 doesn't track
                // namespace member access.
            }
        }
    }
}

fn collect_named_exports(
    file: &std::path::Path,
    decl: &ExportNamedDeclaration<'_>,
    summary: &mut FileSummary,
) {
    let Some(declaration) = &decl.declaration else {
        return;
    };
    match declaration {
        Declaration::FunctionDeclaration(func) => {
            if let Some(name) = func.id.as_ref().map(|id| id.name.to_string())
                && let Some(s) =
                    summarise_function(file, &name, &func.params, func.body.as_deref())
            {
                summary.exports.insert(name, s);
            }
        }
        Declaration::VariableDeclaration(var) => {
            for declarator in &var.declarations {
                let Some(name) = single_binding_name(&declarator.id) else {
                    continue;
                };
                let Some(init) = &declarator.init else { continue };
                if let Some(s) = summarise_initialiser(file, &name, init) {
                    summary.exports.insert(name, s);
                }
            }
        }
        _ => {}
    }
}

fn collect_default_export(
    file: &std::path::Path,
    decl: &ExportDefaultDeclarationKind<'_>,
    summary: &mut FileSummary,
) {
    let s = match decl {
        ExportDefaultDeclarationKind::FunctionDeclaration(func) => {
            summarise_function(file, "default", &func.params, func.body.as_deref())
        }
        ExportDefaultDeclarationKind::ArrowFunctionExpression(arrow) => Some(summarise_arrow(
            file,
            "default",
            &arrow.params,
            &arrow.body,
        )),
        _ => None,
    };
    if let Some(s) = s {
        summary.exports.insert("default".to_string(), s);
    }
}

fn summarise_initialiser(
    file: &std::path::Path,
    name: &str,
    init: &Expression<'_>,
) -> Option<ExportedFunctionSummary> {
    match init {
        Expression::FunctionExpression(func) => {
            summarise_function(file, name, &func.params, func.body.as_deref())
        }
        Expression::ArrowFunctionExpression(arrow) => Some(summarise_arrow(
            file,
            name,
            &arrow.params,
            &arrow.body,
        )),
        _ => None,
    }
}

fn summarise_function(
    file: &std::path::Path,
    name: &str,
    params: &stryx_ast::ast::FormalParameters<'_>,
    body: Option<&FunctionBody<'_>>,
) -> Option<ExportedFunctionSummary> {
    let body_stmts = body.map(|b| b.statements.as_slice()).unwrap_or(&[]);
    Some(build_summary(file, name, params, body_stmts))
}

fn summarise_arrow(
    file: &std::path::Path,
    name: &str,
    params: &stryx_ast::ast::FormalParameters<'_>,
    body: &FunctionBody<'_>,
) -> ExportedFunctionSummary {
    build_summary(file, name, params, &body.statements)
}

fn build_summary(
    file: &std::path::Path,
    name: &str,
    params: &stryx_ast::ast::FormalParameters<'_>,
    body: &[Statement<'_>],
) -> ExportedFunctionSummary {
    let param_names: Vec<String> = params
        .items
        .iter()
        .map(|p| {
            single_binding_name(&p.pattern).unwrap_or_else(|| format!("_arg{}", p.span.start))
        })
        .collect();

    let mut params_out = Vec::with_capacity(param_names.len());
    for pname in &param_names {
        // Run the same flow visitor over the function body with this
        // parameter pre-tainted. If any sink fires, the param sinks to
        // the DB without sanitisation along the path.
        let mut visitor = FlowVisitor::new(file.to_path_buf(), None);
        visitor.enter_fn();
        visitor.taint(pname.clone());
        for stmt in body {
            visitor.handle_statement(stmt);
        }
        visitor.exit_fn();

        let reaches = !visitor.findings.is_empty();
        let sink_span = visitor.findings.first().map(|f| f.span.clone());
        params_out.push(ParamFlow {
            name: pname.clone(),
            reaches_db_sink_unsanitized: reaches,
            sink_span,
        });
    }

    ExportedFunctionSummary {
        name: name.to_string(),
        params: params_out,
        span: Span::new(file.to_path_buf(), params.span.start, params.span.end),
    }
}

fn single_binding_name(pat: &BindingPattern<'_>) -> Option<String> {
    if let BindingPattern::BindingIdentifier(id) = pat {
        Some(id.name.to_string())
    } else {
        None
    }
}

fn walk_binding_pattern(pat: &BindingPattern<'_>, out: &mut Vec<String>) {
    match pat {
        BindingPattern::BindingIdentifier(id) => out.push(id.name.to_string()),
        BindingPattern::ObjectPattern(o) => {
            for prop in &o.properties {
                walk_binding_pattern(&prop.value, out);
                if let PropertyKey::StaticIdentifier(id) = &prop.key
                    && prop.shorthand
                {
                    out.push(id.name.to_string());
                }
            }
        }
        BindingPattern::ArrayPattern(a) => {
            for b in a.elements.iter().flatten() {
                walk_binding_pattern(b, out);
            }
        }
        BindingPattern::AssignmentPattern(a) => walk_binding_pattern(&a.left, out),
    }
}
