//! `flow/unvalidated-body-to-db` — slice 1 (intra-procedural).
//!
//! Detects request-body data flowing into a DB write call (Prisma, generic
//! `db.X.create/update/upsert`) without passing through a parser-style
//! sanitizer (`Schema.parse(...)`, `Schema.safeParse(...)`).
//!
//! Slice 1 is single-file: we walk each function, track which local
//! identifiers carry body taint, and check whether tainted refs reach a
//! DB sink. Slice 2 will plumb `stryx_index` summaries so the same logic
//! follows function calls across module boundaries.

use std::collections::HashSet;
use std::path::PathBuf;

use stryx_ast::{
    ast::{
        ArrowFunctionExpression, BindingPattern, CallExpression, Expression,
        Function, MemberExpression, ObjectPropertyKind, PropertyKey, Statement,
        VariableDeclaration,
    },
    to_span, ScopeFlags, Visit,
};
use stryx_core::{Finding, Severity};

use crate::{Rule, RuleContext, RuleMeta};

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

    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding> {
        let mut visitor = FlowVisitor::new(ctx.file.path.clone());
        visitor.visit_program(&ctx.file.program);
        visitor.findings
    }
}

struct FlowVisitor {
    file: PathBuf,
    findings: Vec<Finding>,
    /// Stack of per-function scopes. Each frame holds the names of local
    /// identifiers currently carrying request-body taint.
    scopes: Vec<HashSet<String>>,
}

impl FlowVisitor {
    fn new(file: PathBuf) -> Self {
        Self {
            file,
            findings: Vec::new(),
            scopes: Vec::new(),
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

impl<'a> Visit<'a> for FlowVisitor {
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
