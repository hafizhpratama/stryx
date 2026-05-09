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
        ExportDefaultDeclarationKind, ExportNamedDeclaration, Expression, FormalParameter,
        Function, FunctionBody, ImportDeclaration, ImportDeclarationSpecifier,
        ImportOrExportKind, LogicalOperator, MemberExpression, ObjectPropertyKind,
        Program, PropertyKey, Statement, TSType, TSTypeName, UnaryOperator,
        VariableDeclaration,
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
        Some(extract_summary(
            ctx.file.path.clone(),
            &ctx.file.program,
            ctx.index,
        ))
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
    /// Set true by `handle_statement` when a `return <expr>` is reached
    /// and `<expr>` is tainted. The per-parameter simulation in
    /// `build_summary` reads this to populate
    /// `ParamFlow::propagates_to_return`.
    tainted_return: bool,
}

impl<'idx> FlowVisitor<'idx> {
    fn new(file: PathBuf, index: Option<&'idx stryx_index::ProjectIndex>) -> Self {
        Self {
            file,
            findings: Vec::new(),
            scopes: Vec::new(),
            index,
            tainted_return: false,
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

    /// If the callee resolves through the project index to a known
    /// exported function, return that summary. Used by call-site taint
    /// propagation to avoid spurious propagation through helpers that
    /// transform their input into something different.
    fn lookup_callee_summary(
        &self,
        callee: &Expression<'_>,
    ) -> Option<&'idx stryx_taint::ExportedFunctionSummary> {
        let index = self.index?;
        let Expression::Identifier(id) = callee else {
            return None;
        };
        let name = id.name.as_str();
        // Cross-file: resolve through the import map.
        if let Some(s) = index.resolve_summary(&self.file, name) {
            return Some(s);
        }
        // Same-file: look up a top-level function declared in this file
        // (exported or local).
        let file = index.file(&self.file)?;
        file.exports.get(name).or_else(|| file.locals.get(name))
    }

    /// Should taint at argument position `i` propagate through this call
    /// site? When the callee has a known summary we trust it; otherwise
    /// we default to conservative propagation (true).
    fn callee_propagates_arg(
        &self,
        summary: Option<&stryx_taint::ExportedFunctionSummary>,
        i: usize,
    ) -> bool {
        match summary {
            Some(s) => s.params.get(i).is_none_or(|p| p.propagates_to_return),
            None => true,
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
                    if self.expr_taint(arg) {
                        self.tainted_return = true;
                    }
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
                // Allow-list narrowing: an early-return guard of the
                // shape `if (...!ARR.includes(x)...) return ...` proves
                // that `x` is one of ARR's elements past this point.
                // Drop its taint for the remainder of the scope.
                if branch_returns(&is.consequent) {
                    let mut narrowed = Vec::new();
                    collect_includes_narrowed(&is.test, &mut narrowed);
                    for name in narrowed {
                        if let Some(scope) = self.current_scope_mut() {
                            scope.remove(&name);
                        }
                    }
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
                // For any other call, taint propagates if a tainted
                // argument flows into a parameter the callee actually
                // returns. When the callee has no known summary
                // (third-party imports, dynamic calls), we fall back to
                // conservative propagation. Sink scanning happens in
                // `scan_for_sinks` which walks the whole expression tree;
                // doing it here too would double-emit findings on
                // chained calls like `db.insert(t).values(body).run()`.
                let summary = self.lookup_callee_summary(&call.callee);
                let mut any_tainted = false;
                for (i, arg) in call.arguments.iter().enumerate() {
                    let Some(e) = arg.as_expression() else { continue };
                    if self.expr_taint(e) && self.callee_propagates_arg(summary, i) {
                        any_tainted = true;
                    }
                }
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
                let summary = self.lookup_callee_summary(&call.callee);
                call.arguments.iter().enumerate().any(|(i, arg)| {
                    arg.as_expression()
                        .map(|e| {
                            self.expr_is_tainted_readonly(e)
                                && self.callee_propagates_arg(summary, i)
                        })
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
        // NestJS and similar frameworks declare body sources via parameter
        // decorators (`@Body() dto: CreateUserDto`). Pre-taint any param
        // marked with one — the framework will inject body data there.
        for name in body_decorated_param_names(&func.params) {
            self.taint(name);
        }
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
    let Some(callee) = call.callee.as_member_expression() else {
        return false;
    };
    let MemberExpression::StaticMemberExpression(method) = callee else {
        return false;
    };
    let prop = method.property.name.as_str();

    // Zod / valibot / yup parser style: any object exposing
    // `.parse`, `.safeParse`, `.parseAsync`, `.safeParseAsync`. Covers
    // `Schema.parse(body)`, `CreateUserSchema.safeParse(...)`, etc.
    if matches!(
        prop,
        "parse" | "safeParse" | "parseAsync" | "safeParseAsync"
    ) {
        return true;
    }

    // Stripe webhook signature verification:
    //   `stripe.webhooks.constructEvent(body, signature, secret)`
    // Throws on bad signature; on success returns a verified Stripe.Event
    // whose shape is enforced by the Stripe SDK. Treat it as a sanitiser.
    if prop == "constructEvent"
        && let Expression::StaticMemberExpression(inner) = &method.object
        && inner.property.name == "webhooks"
    {
        return true;
    }

    false
}

fn is_db_read_call(call: &CallExpression<'_>) -> bool {
    let Some(callee) = call.callee.as_member_expression() else {
        return false;
    };
    let MemberExpression::StaticMemberExpression(method) = callee else {
        return false;
    };
    let prop = method.property.name.as_str();

    // Prisma read methods on a `prisma.<model>` chain. The result is
    // a typed DB row; we treat it as clean even when the where-clause
    // carries taint.
    const PRISMA_READS: &[&str] = &[
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
    if PRISMA_READS.contains(&prop)
        && let Expression::StaticMemberExpression(model_member) = &method.object
        && let Expression::Identifier(root_id) = &model_member.object
        && matches!(root_id.name.as_str(), "prisma" | "db" | "database")
    {
        return true;
    }

    // Drizzle read chains: `db.select(...).from(t).where(c).orderBy(...)`
    // and so on. Each call in the chain returns a query builder whose
    // eventual rows are typed by the schema, not by the tainted where-
    // clause. Treat the chain's intermediate calls as reads so taint
    // doesn't leak into the result. Write terminators like `.values`
    // and `.set` are handled separately by `is_drizzle_write_sink`.
    const DRIZZLE_READS: &[&str] = &[
        "select",
        "from",
        "where",
        "orderBy",
        "limit",
        "offset",
        "groupBy",
        "having",
        "innerJoin",
        "leftJoin",
        "rightJoin",
        "fullJoin",
        "all",
        "get",
        "execute",
        "returning",
    ];
    if DRIZZLE_READS.contains(&prop) {
        return true;
    }

    false
}

/// Top-level sink matcher: returns true if `call` is a DB write across
/// any recognised ORM. Shapes covered:
/// - Prisma: `<prisma|db|database>.<model>.<crud>(...)`
/// - Drizzle: `<chain>.values(...)` after `<x>.insert(t)`,
///   `<chain>.set(...)` after `<x>.update(t)`
/// - TypeORM/Mongoose-ish: `<expr>.save(...)`, `<expr>.insert(...)`,
///   `<expr>.upsert(...)` on any receiver — these verbs are
///   DB-specific enough that we don't gate on the receiver shape.
fn is_db_write_sink(call: &CallExpression<'_>) -> bool {
    is_prisma_write_sink(call) || is_drizzle_write_sink(call) || is_orm_write_sink(call)
}

fn is_prisma_write_sink(call: &CallExpression<'_>) -> bool {
    // Prisma-shape: <prisma|db|database>.<model>.<method>
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
    let Expression::StaticMemberExpression(model_member) = &method.object else {
        return false;
    };
    let Expression::Identifier(root_id) = &model_member.object else {
        return false;
    };
    matches!(root_id.name.as_str(), "prisma" | "db" | "database")
}

fn is_drizzle_write_sink(call: &CallExpression<'_>) -> bool {
    // Drizzle-shape: `<x>.insert(table).values(arg)` / `<x>.update(table).set(arg)`.
    // The terminal call is `<chain>.values` or `<chain>.set` and the
    // chain itself contains an `.insert` or `.update` call.
    let Some(callee) = call.callee.as_member_expression() else {
        return false;
    };
    let MemberExpression::StaticMemberExpression(terminal) = callee else {
        return false;
    };
    let expected_inner = match terminal.property.name.as_str() {
        "values" => "insert",
        "set" => "update",
        _ => return false,
    };
    // The receiver of the terminal call must itself be a `.insert(...)`
    // or `.update(...)` call.
    let Expression::CallExpression(inner_call) = &terminal.object else {
        return false;
    };
    let Some(inner_callee) = inner_call.callee.as_member_expression() else {
        return false;
    };
    let MemberExpression::StaticMemberExpression(inner_method) = inner_callee else {
        return false;
    };
    inner_method.property.name.as_str() == expected_inner
}

fn is_orm_write_sink(call: &CallExpression<'_>) -> bool {
    // TypeORM / Mongoose / generic ORM: `<receiver>.save(...)`,
    // `<receiver>.insert(...)`, `<receiver>.upsert(...)`. We don't
    // restrict the receiver shape — these verbs are DB-specific enough
    // that any tainted argument arriving here is worth flagging.
    if call.arguments.is_empty() {
        return false;
    }
    let Some(callee) = call.callee.as_member_expression() else {
        return false;
    };
    let MemberExpression::StaticMemberExpression(method) = callee else {
        return false;
    };
    matches!(method.property.name.as_str(), "save" | "insert" | "upsert")
}

/// True if the body of an if-branch is guaranteed to leave the
/// enclosing scope (return / throw). Used to recognise early-return
/// guards.
fn branch_returns(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::ReturnStatement(_) | Statement::ThrowStatement(_) => true,
        Statement::BlockStatement(b) => b.body.iter().any(branch_returns),
        _ => false,
    }
}

/// Collect identifiers narrowed by `!ARR.includes(IDENT)` clauses
/// inside an OR-chain. Each such clause inside an early-return guard
/// proves that `IDENT` is one of `ARR`'s literal elements past the
/// guard, so we can clear its taint.
fn collect_includes_narrowed(test: &Expression<'_>, out: &mut Vec<String>) {
    match test {
        Expression::LogicalExpression(b) if b.operator == LogicalOperator::Or => {
            collect_includes_narrowed(&b.left, out);
            collect_includes_narrowed(&b.right, out);
        }
        _ => {
            if let Some(name) = match_includes_negation(test) {
                out.push(name.to_string());
            }
        }
    }
}

fn match_includes_negation<'a>(expr: &'a Expression<'_>) -> Option<&'a str> {
    let Expression::UnaryExpression(unary) = expr else {
        return None;
    };
    if unary.operator != UnaryOperator::LogicalNot {
        return None;
    }
    let Expression::CallExpression(call) = &unary.argument else {
        return None;
    };
    let callee = call.callee.as_member_expression()?;
    let MemberExpression::StaticMemberExpression(method) = callee else {
        return None;
    };
    if method.property.name != "includes" {
        return None;
    }
    // Receiver should be a literal array (the allow-list itself).
    if !matches!(&method.object, Expression::ArrayExpression(_)) {
        return None;
    }
    if call.arguments.len() != 1 {
        return None;
    }
    let arg_expr = call.arguments[0].as_expression()?;
    let Expression::Identifier(id) = arg_expr else {
        return None;
    };
    Some(id.name.as_str())
}

/// Names of parameters carrying a body-source decorator (`@Body()` or
/// `@Body`). NestJS controllers declare their body argument this way.
///
/// Heuristic: when the parameter's TS type annotation looks like a
/// validated DTO (suffix `Dto` / `DTO` / `Input` / `Schema` /
/// `Request`), assume NestJS's `ValidationPipe` runs class-validator
/// against the DTO before the body reaches user code, and don't pre-
/// taint. The framework provides validation we can't see — the
/// type-name convention is the cheapest signal we can read locally.
fn body_decorated_param_names(params: &stryx_ast::ast::FormalParameters<'_>) -> Vec<String> {
    let mut out = Vec::new();
    for param in &params.items {
        if !param.decorators.iter().any(is_body_decorator) {
            continue;
        }
        if looks_like_validated_dto(param) {
            continue;
        }
        if let Some(name) = single_binding_name(&param.pattern) {
            out.push(name);
        }
    }
    out
}

fn looks_like_validated_dto(param: &FormalParameter<'_>) -> bool {
    let Some(annotation) = &param.type_annotation else {
        return false;
    };
    let TSType::TSTypeReference(tref) = &annotation.type_annotation else {
        return false;
    };
    let TSTypeName::IdentifierReference(id) = &tref.type_name else {
        return false;
    };
    let name = id.name.as_str();
    name.ends_with("Dto")
        || name.ends_with("DTO")
        || name.ends_with("Input")
        || name.ends_with("InputDto")
        || name.ends_with("Schema")
        || name.ends_with("Request")
}

fn is_body_decorator(decorator: &stryx_ast::ast::Decorator<'_>) -> bool {
    let target = match &decorator.expression {
        // `@Body()` — call expression with `Body` as callee.
        Expression::CallExpression(call) => &call.callee,
        // `@Body` — bare identifier.
        other => other,
    };
    matches!(
        target,
        Expression::Identifier(id) if id.name.as_str() == "Body"
    )
}

fn callee_chain(expr: &Expression<'_>) -> Option<String> {
    match expr {
        Expression::Identifier(id) => Some(id.name.to_string()),
        Expression::ThisExpression(_) => Some("this".to_string()),
        Expression::StaticMemberExpression(m) => {
            let lhs = callee_chain(&m.object)?;
            Some(format!("{lhs}.{}", m.property.name))
        }
        // Show drizzle-style chains like `db.insert(...).values` rather
        // than collapsing to "db sink".
        Expression::CallExpression(call) => {
            let inner = callee_chain(&call.callee)?;
            Some(format!("{inner}(...)"))
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
            Statement::ImportDeclaration(decl) => {
                collect_imports(decl, &mut summary);
            }
            Statement::ExportNamedDeclaration(decl) => {
                collect_named_exports(&file, decl, index, &mut summary);
            }
            Statement::ExportDefaultDeclaration(decl) => {
                collect_default_export(&file, &decl.declaration, index, &mut summary);
            }
            // Top-level non-exported functions: summarise as locals so
            // same-file helpers participate in propagation decisions.
            Statement::FunctionDeclaration(func) => {
                if let Some(name) = func.id.as_ref().map(|id| id.name.to_string())
                    && let Some(s) = summarise_function(
                        &file,
                        &name,
                        &func.params,
                        func.body.as_deref(),
                        index,
                    )
                {
                    summary.locals.insert(name, s);
                }
            }
            // Same for `const foo = (...) => {...}` at the top level.
            Statement::VariableDeclaration(var) => {
                for declarator in &var.declarations {
                    let Some(name) = single_binding_name(&declarator.id) else {
                        continue;
                    };
                    let Some(init) = &declarator.init else { continue };
                    if let Some(s) = summarise_initialiser(&file, &name, init, index) {
                        summary.locals.insert(name, s);
                    }
                }
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
    index: Option<&stryx_index::ProjectIndex>,
    summary: &mut FileSummary,
) {
    let Some(declaration) = &decl.declaration else {
        return;
    };
    match declaration {
        Declaration::FunctionDeclaration(func) => {
            if let Some(name) = func.id.as_ref().map(|id| id.name.to_string())
                && let Some(s) = summarise_function(
                    file,
                    &name,
                    &func.params,
                    func.body.as_deref(),
                    index,
                )
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
                if let Some(s) = summarise_initialiser(file, &name, init, index) {
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
    index: Option<&stryx_index::ProjectIndex>,
    summary: &mut FileSummary,
) {
    let s = match decl {
        ExportDefaultDeclarationKind::FunctionDeclaration(func) => summarise_function(
            file,
            "default",
            &func.params,
            func.body.as_deref(),
            index,
        ),
        ExportDefaultDeclarationKind::ArrowFunctionExpression(arrow) => Some(summarise_arrow(
            file,
            "default",
            &arrow.params,
            &arrow.body,
            index,
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
    index: Option<&stryx_index::ProjectIndex>,
) -> Option<ExportedFunctionSummary> {
    match init {
        Expression::FunctionExpression(func) => {
            summarise_function(file, name, &func.params, func.body.as_deref(), index)
        }
        Expression::ArrowFunctionExpression(arrow) => Some(summarise_arrow(
            file,
            name,
            &arrow.params,
            &arrow.body,
            index,
        )),
        _ => None,
    }
}

fn summarise_function(
    file: &std::path::Path,
    name: &str,
    params: &stryx_ast::ast::FormalParameters<'_>,
    body: Option<&FunctionBody<'_>>,
    index: Option<&stryx_index::ProjectIndex>,
) -> Option<ExportedFunctionSummary> {
    let body_stmts = body.map(|b| b.statements.as_slice()).unwrap_or(&[]);
    Some(build_summary(file, name, params, body_stmts, index))
}

fn summarise_arrow(
    file: &std::path::Path,
    name: &str,
    params: &stryx_ast::ast::FormalParameters<'_>,
    body: &FunctionBody<'_>,
    index: Option<&stryx_index::ProjectIndex>,
) -> ExportedFunctionSummary {
    build_summary(file, name, params, &body.statements, index)
}

fn build_summary(
    file: &std::path::Path,
    name: &str,
    params: &stryx_ast::ast::FormalParameters<'_>,
    body: &[Statement<'_>],
    index: Option<&stryx_index::ProjectIndex>,
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
        // Run the flow visitor over the function body with just this
        // parameter pre-tainted. The visitor consults the *previous
        // iteration's* index, so cross-file calls already known to sink
        // contribute too — that's what makes summaries converge through
        // multi-level chains (controller → service → repository).
        let mut visitor = FlowVisitor::new(file.to_path_buf(), index);
        visitor.enter_fn();
        visitor.taint(pname.clone());
        for stmt in body {
            visitor.handle_statement(stmt);
        }
        visitor.exit_fn();

        let reaches = !visitor.findings.is_empty();
        let sink_span = visitor.findings.first().map(|f| f.span.clone());
        let propagates_to_return = visitor.tainted_return;
        params_out.push(ParamFlow {
            name: pname.clone(),
            reaches_db_sink_unsanitized: reaches,
            propagates_to_return,
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
