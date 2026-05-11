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
    ScopeFlags, Visit,
    ast::{
        Argument, ArrowFunctionExpression, BinaryOperator, BindingPattern, CallExpression,
        ChainElement, Class, ClassElement, Declaration, ExportDefaultDeclarationKind,
        ExportNamedDeclaration, Expression, FormalParameter, Function, FunctionBody,
        ImportDeclaration, ImportDeclarationSpecifier, ImportOrExportKind, LogicalOperator,
        MemberExpression, MethodDefinitionKind, ObjectPropertyKind, Program, PropertyKey,
        Statement, SwitchCase, TSType, TSTypeName, UnaryOperator, VariableDeclaration,
    },
    to_span,
};
use stryx_core::{Finding, Severity, Span};
use stryx_index::{ClassInfo, FileSummary, ImportRef};
use stryx_taint::{Cell, ExportedFunctionSummary, Offset, ParamFlow, Shape, TaintLabel, Xtaint};

use crate::steps::sanitizers::{ParserSanitizer, is_sanitizer_call};
use crate::steps::sinks::{
    DrizzleWriteSink, OrmWriteSink, PrismaWriteSink, is_db_write_sink, is_prisma_write_sink,
};
use crate::steps::sources::{BodySource, is_body_source_call, is_request_body_member};
use crate::steps::{StepCtx, StepKind};

/// Closed-enum step registry consulted by `FlowVisitor`. Each
/// variant maps onto one of the four taint roles (source/sink/
/// sanitizer/propagator) and is queried via the matching
/// `registry_as_*` helper. ADR 0008 slices migrate predicates one
/// role at a time.
const RULE_STEPS: &[StepKind] = &[
    // Slice 8.2 — body-source recogniser (Next.js + Hono).
    StepKind::BodySource(BodySource),
    // Slice 8.3a — parser-style sanitiser (zod/valibot/yup +
    // conform `parse(x, { schema })` + Stripe webhook constructEvent).
    StepKind::ParserSanitizer(ParserSanitizer),
    // Slice 8.4 — DB write sinks across Prisma, Drizzle, and
    // generic TypeORM/Mongoose shapes.
    StepKind::PrismaWriteSink(PrismaWriteSink),
    StepKind::DrizzleWriteSink(DrizzleWriteSink),
    StepKind::OrmWriteSink(OrmWriteSink),
];

use super::auth_bypass_via_wrapper::contains_auth_helper_call;

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
        visitor.collect_allow_lists(&ctx.file.program);
        // Pull pre-validated handler names from the file's summary,
        // built during the extract pass. Inside these handlers, body
        // taint sourcing is suppressed.
        if let Some(index) = ctx.index
            && let Some(summary) = index.file(&ctx.file.path)
        {
            visitor
                .body_validated_handlers
                .clone_from(&summary.body_validated_handlers);
        }
        visitor.visit_program(&ctx.file.program);
        visitor.findings
    }
}

struct FlowVisitor<'idx> {
    file: PathBuf,
    findings: Vec<Finding>,
    /// Stack of per-function scopes. Each frame maps the name of a
    /// tainted local identifier to its tracked [`Cell`] shape.
    /// Pre-Phase-3 the stack was `Vec<HashSet<String>>` (just names);
    /// per-local shape tracking was added as substrate for slice 3.5
    /// (cross-file return-shape propagation at variable bindings).
    /// `taint(name)` continues to insert `Cell::tainted([UserInput])`
    /// for backward compatibility; `taint_with_shape(name, cell)`
    /// lets callers attach a richer shape when they know one.
    scopes: Vec<std::collections::HashMap<String, Cell>>,
    /// Read-only project index; `Some` during the run pass, `None`
    /// during summary extraction.
    index: Option<&'idx stryx_index::ProjectIndex>,
    /// Set true by `handle_statement` when a `return <expr>` is reached
    /// and `<expr>` is tainted. The per-parameter simulation in
    /// `build_summary` reads this to populate
    /// `ParamFlow::propagates_to_return`.
    tainted_return: bool,
    /// Top-level `const NAME = [literal, literal, ...]` allow-list
    /// declarations seen in this file. Used so that
    /// `if (!ALLOWED.includes(x)) return ...` narrows even when `ALLOWED`
    /// is a hoisted const rather than an inline array literal.
    allow_lists: HashSet<String>,
    /// Stack of class names currently being visited. Used inside class
    /// methods so `this.<member>.<method>(arg)` can resolve `<member>`
    /// against the enclosing class's `field_types`.
    class_stack: Vec<String>,
    /// Names of handlers whose `req.body` is suppressed as a taint
    /// source — populated from
    /// `FileSummary::body_validated_handlers` at run time.
    body_validated_handlers: HashSet<String>,
    /// Suppression depth. Incremented when entering a function that
    /// matches `body_validated_handlers`; while > 0, body-source
    /// recognition (`req.body`, `req.json()`, `@Body()` decorator
    /// pre-taint) is disabled.
    body_source_suppressed: u32,
    /// Last-seen binding-identifier name from a `VariableDeclarator`,
    /// consumed by the next `visit_arrow_function_expression` /
    /// `visit_function` to recover the function's effective name for
    /// arrow / anonymous-function expressions assigned to a const.
    pending_binding_name: Option<String>,
    /// Slice 2.1c of ADR 0006 — full-chain shape of observed tainted
    /// reads, accumulated as a `Cell` tree. `body.where.id` produces a
    /// nested `Obj { where -> Obj { id -> Tainted } }`; multiple chain
    /// observations merge into the same tree (shared prefixes share
    /// intermediate cells). Drained in `build_summary` via
    /// `Cell::canonicalize` before being attached to `ParamFlow`.
    ///
    /// Slice 2.5 made this the single source of truth: the legacy
    /// `tainted_offsets` and `reaches_db_sink_unsanitized` fields on
    /// `ParamFlow` are now derived from the canonicalized shape via
    /// `Cell::top_tainted_offsets()` and `Cell::has_tainted_leaf()`.
    /// The previous `top_offsets_seen: HashSet<Offset>` parallel
    /// state is gone.
    param_shape_seen: Cell,
    /// Slice 3.1 of ADR 0007 — full-chain shape of what flows through
    /// return statements. Same recording model as `param_shape_seen`,
    /// but driven by `Statement::ReturnStatement` rather than sink
    /// calls. The drain attaches to `ParamFlow.return_shape`.
    ///
    /// `tainted_return: bool` continues to ship and is set in lockstep;
    /// slice 3.7 will collapse it onto a derived accessor once
    /// consumers migrate.
    return_shape_seen: Cell,
}

impl<'idx> FlowVisitor<'idx> {
    fn new(file: PathBuf, index: Option<&'idx stryx_index::ProjectIndex>) -> Self {
        Self {
            file,
            findings: Vec::new(),
            scopes: Vec::new(),
            index,
            tainted_return: false,
            allow_lists: HashSet::new(),
            class_stack: Vec::new(),
            body_validated_handlers: HashSet::new(),
            body_source_suppressed: 0,
            pending_binding_name: None,
            param_shape_seen: Cell::bot(),
            return_shape_seen: Cell::bot(),
        }
    }

    fn enter_fn(&mut self) {
        self.scopes.push(std::collections::HashMap::new());
    }

    fn exit_fn(&mut self) {
        self.scopes.pop();
    }

    fn current_scope_mut(&mut self) -> Option<&mut std::collections::HashMap<String, Cell>> {
        self.scopes.last_mut()
    }

    fn is_tainted(&self, name: &str) -> bool {
        self.scopes
            .iter()
            .rev()
            .any(|scope| scope.contains_key(name))
    }

    /// Look up the tracked shape of a tainted local. Returns `None` if
    /// the name isn't tainted in any active scope. Slice 2.5+ ground
    /// truth: callers that need to consume the local's shape (e.g.
    /// the cross-file return-shape consumer in slice 3.5) should
    /// read this.
    #[allow(dead_code)]
    fn local_shape(&self, name: &str) -> Option<&Cell> {
        for scope in self.scopes.iter().rev() {
            if let Some(cell) = scope.get(name) {
                return Some(cell);
            }
        }
        None
    }

    /// Body-source recognition gated by the validation-wrapper
    /// suppression depth. When the visitor is inside a handler whose
    /// outer wrapper validates `req.body` against a schema, both
    /// `req.body`-shape access and `req.json()`-shape calls are
    /// treated as already-clean — the wrapper has already enforced
    /// the schema before delegating, so the inner handler's body
    /// reads are guaranteed to be structured.
    fn body_source_active(&self) -> bool {
        self.body_source_suppressed == 0
    }

    fn matches_body_member(&self, object: &Expression<'_>, prop: &str) -> bool {
        self.body_source_active() && is_request_body_member(object, prop)
    }

    fn matches_body_call(&self, call: &CallExpression<'_>) -> bool {
        self.body_source_active() && is_body_source_call(call)
    }

    /// Slice 8.2 of ADR 0008 — construct the read-only [`StepCtx`]
    /// every step recogniser consumes. Pulled from visitor state at
    /// call time; cheap, no allocation.
    fn step_ctx(&self) -> StepCtx<'_, 'idx> {
        StepCtx {
            file: &self.file,
            index: self.index,
            body_source_active: self.body_source_active(),
        }
    }

    /// Slice 8.2 of ADR 0008 — registry-dispatched source check.
    /// Iterates [`RULE_STEPS`] and returns the first matching
    /// label, or `None` if no step recognises `expr` as a source.
    /// Closed-enum dispatch over `StepKind`; release builds compile
    /// to a jump table.
    fn registry_as_source(&self, expr: &Expression<'_>) -> Option<TaintLabel> {
        let ctx = self.step_ctx();
        for step in RULE_STEPS {
            if let Some(label) = step.as_source(&ctx, expr) {
                return Some(label);
            }
        }
        None
    }

    /// Slice 8.3a of ADR 0008 — registry-dispatched sanitiser check.
    /// Returns `true` if any [`RULE_STEPS`] entry recognises `call`
    /// as a sanitiser; same closed-enum dispatch shape as
    /// `registry_as_source`.
    fn registry_as_sanitizer(&self, call: &CallExpression<'_>) -> bool {
        let ctx = self.step_ctx();
        RULE_STEPS.iter().any(|step| step.as_sanitizer(&ctx, call))
    }

    /// Slice 8.4 of ADR 0008 — registry-dispatched sink check.
    /// Returns the first matching `SinkSpec` (severity hint) or
    /// `None` if no [`RULE_STEPS`] entry recognises `call` as a
    /// sink. Closed-enum dispatch; release builds compile to a
    /// jump table.
    fn registry_as_sink(&self, call: &CallExpression<'_>) -> Option<crate::steps::SinkSpec> {
        let ctx = self.step_ctx();
        for step in RULE_STEPS {
            if let Some(spec) = step.as_sink(&ctx, call) {
                return Some(spec);
            }
        }
        None
    }

    fn taint(&mut self, name: String) {
        // Default: whole-value taint (`Tainted+Bot`). Most callers
        // don't yet track shape on the RHS — this preserves the
        // pre-Phase-3 behavior for `is_tainted(name)` checks while
        // letting future call sites use `taint_with_shape` to
        // attach precision when they have it.
        self.taint_with_shape(name, Cell::tainted(vec![TaintLabel::UserInput]));
    }

    /// Track `name` as carrying the given `Cell` shape in the current
    /// scope. Callers with a known shape (e.g. slice 3.5's variable-
    /// declarator consumer that calls `instantiate_tainted` on a
    /// callee's return_shape) use this directly.
    #[allow(dead_code)]
    fn taint_with_shape(&mut self, name: String, cell: Cell) {
        if let Some(scope) = self.current_scope_mut() {
            scope.insert(name, cell);
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
        match callee {
            Expression::Identifier(id) => {
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
            Expression::StaticMemberExpression(m) => {
                // `this.<method>(...)` — same-class call.
                if matches!(&m.object, Expression::ThisExpression(_)) {
                    let method = m.property.name.as_str();
                    let current_class = self.class_stack.last()?;
                    let my_file = index.file(&self.file)?;
                    let class_info = my_file.classes.get(current_class)?;
                    return class_info.methods.get(method);
                }
                // `this.<member>.<method>(...)` — call to an injected
                // service. Resolve `<member>` to its declared TS type
                // name in the enclosing class, then look up that class's
                // `<method>` in this file or via imports.
                if let Expression::StaticMemberExpression(inner) = &m.object
                    && matches!(&inner.object, Expression::ThisExpression(_))
                {
                    let member = inner.property.name.as_str();
                    let method = m.property.name.as_str();
                    return self.lookup_this_method_summary(member, method);
                }
                None
            }
            _ => None,
        }
    }

    /// Resolve `this.<member>.<method>` to a method summary, where
    /// `<member>` is a field/parameter-property whose declared type
    /// names a class we can find in this file or via an import.
    fn lookup_this_method_summary(
        &self,
        member: &str,
        method: &str,
    ) -> Option<&'idx stryx_taint::ExportedFunctionSummary> {
        let index = self.index?;
        let current_class = self.class_stack.last()?;
        let my_file = index.file(&self.file)?;
        let class_info = my_file.classes.get(current_class)?;
        let type_name = class_info.field_types.get(member)?;
        // Same-file class declaration first.
        if let Some(target) = my_file.classes.get(type_name)
            && let Some(s) = target.methods.get(method)
        {
            return Some(s);
        }
        // Cross-file via the import map.
        let (target_file, exported_name) = index.resolve_class(&self.file, type_name)?;
        target_file.classes.get(exported_name)?.methods.get(method)
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

    /// Pre-pass: scan the file's top-level statements for
    /// `const NAME = [literal, literal, ...]` declarations and record
    /// each NAME as an allow-list. Lets the run-pass narrowing detector
    /// recognise `ALLOWED.includes(x)` (Identifier receiver) the same
    /// way it recognises an inline-array `["a","b"].includes(x)`.
    fn collect_allow_lists(&mut self, program: &Program<'_>) {
        for stmt in &program.body {
            let var = match stmt {
                Statement::VariableDeclaration(v) => v,
                Statement::ExportNamedDeclaration(decl) => match decl.declaration.as_ref() {
                    Some(Declaration::VariableDeclaration(v)) => v,
                    _ => continue,
                },
                _ => continue,
            };
            for declarator in &var.declarations {
                let Some(name) = single_binding_name(&declarator.id) else {
                    continue;
                };
                let Some(init) = &declarator.init else {
                    continue;
                };
                let array_expr = match init {
                    Expression::ArrayExpression(a) => a,
                    Expression::TSAsExpression(t) => match &t.expression {
                        Expression::ArrayExpression(a) => a,
                        _ => continue,
                    },
                    _ => continue,
                };
                if array_expr.elements.iter().all(|el| {
                    matches!(
                        el.as_expression(),
                        Some(
                            Expression::StringLiteral(_)
                                | Expression::NumericLiteral(_)
                                | Expression::BooleanLiteral(_)
                        )
                    )
                }) {
                    self.allow_lists.insert(name);
                }
            }
        }
    }

    fn handle_switch_case(&mut self, case: &SwitchCase<'_>) {
        if let Some(test) = &case.test {
            let _ = self.expr_taint(test);
        }
        for s in &case.consequent {
            self.handle_statement(s);
        }
    }

    /// Taint each binding introduced by a `for-of` / `for-in` left side.
    /// Handles `for (const x of ...)` / `for (let x of ...)` / pattern
    /// destructuring; `for (existing of ...)` (assignment target without
    /// declaration) is handled in the catch-all branch.
    fn taint_for_left(&mut self, left: &stryx_ast::ast::ForStatementLeft<'_>) {
        use stryx_ast::ast::ForStatementLeft;
        match left {
            ForStatementLeft::VariableDeclaration(decl) => {
                for declarator in &decl.declarations {
                    for name in collect_binding_names(&declarator.id) {
                        self.taint(name);
                    }
                }
            }
            ForStatementLeft::AssignmentTargetIdentifier(id) => {
                self.taint(id.name.to_string());
            }
            _ => {}
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
                    // Slice 3.1 of ADR 0007 — record return-shape
                    // observations alongside the existing boolean.
                    // Observation-only; `tainted_return` remains the
                    // source of truth through Phase 3's window.
                    self.record_taint_in_return(arg);
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
                // Drop its taint for the remainder of the scope. ARR can
                // be either a literal array or a hoisted `const`
                // allow-list (collected in `collect_allow_lists`).
                if branch_returns(&is.consequent) {
                    let mut narrowed = Vec::new();
                    collect_includes_narrowed(&is.test, &self.allow_lists, &mut narrowed);
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
            Statement::WhileStatement(ws) => {
                let _ = self.expr_taint(&ws.test);
                self.handle_statement(&ws.body);
            }
            Statement::DoWhileStatement(ds) => {
                self.handle_statement(&ds.body);
                let _ = self.expr_taint(&ds.test);
            }
            Statement::ForStatement(fs) => {
                if let Some(init) = &fs.init {
                    use stryx_ast::ast::ForStatementInit;
                    match init {
                        ForStatementInit::VariableDeclaration(v) => self.handle_var_decl(v),
                        other => {
                            // Inherit-variant: any Expression. Walk for taint
                            // side effects.
                            if let Some(e) = expression_from_for_init(other) {
                                let _ = self.expr_taint(e);
                                self.scan_for_sinks(e);
                            }
                        }
                    }
                }
                if let Some(test) = &fs.test {
                    let _ = self.expr_taint(test);
                }
                if let Some(update) = &fs.update {
                    let _ = self.expr_taint(update);
                    self.scan_for_sinks(update);
                }
                self.handle_statement(&fs.body);
            }
            Statement::ForOfStatement(fs) => {
                let right_tainted = self.expr_taint(&fs.right);
                self.scan_for_sinks(&fs.right);
                // Each iteration's loop binding takes one element of the
                // (possibly tainted) iterable, so it inherits the iterable's
                // taint. `for (const x of body.items) sink(x)` therefore
                // flags x correctly.
                if right_tainted {
                    self.taint_for_left(&fs.left);
                }
                self.handle_statement(&fs.body);
            }
            Statement::ForInStatement(fs) => {
                let right_tainted = self.expr_taint(&fs.right);
                self.scan_for_sinks(&fs.right);
                if right_tainted {
                    self.taint_for_left(&fs.left);
                }
                self.handle_statement(&fs.body);
            }
            Statement::SwitchStatement(ss) => {
                let _ = self.expr_taint(&ss.discriminant);
                self.scan_for_sinks(&ss.discriminant);
                for case in &ss.cases {
                    self.handle_switch_case(case);
                }
            }
            Statement::LabeledStatement(ls) => {
                self.handle_statement(&ls.body);
            }
            Statement::ThrowStatement(ts) => {
                let _ = self.expr_taint(&ts.argument);
                self.scan_for_sinks(&ts.argument);
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
            let Some(init) = &declarator.init else {
                continue;
            };
            let tainted = self.expr_taint(init);
            self.scan_for_sinks(init);
            if !tainted {
                continue;
            }
            // Slice 3.5 of ADR 0007 — try to compute a precise return
            // shape for `const x = helper(arg)` patterns. Falls
            // through to plain `taint(name)` if the call doesn't
            // resolve, isn't a single-binding pattern, or yields
            // nothing more precise than whole-value taint.
            let names: Vec<String> = collect_binding_names(&declarator.id);
            if names.len() == 1
                && let Some(shape) = self.compute_call_return_shape(init)
            {
                let name = names.into_iter().next().unwrap();
                self.taint_with_shape(name, shape);
                continue;
            }
            // Default: whole-value taint for each binding (preserves
            // pre-3.5 behavior on destructuring and non-call inits).
            for name in names {
                self.taint(name);
            }
        }
    }

    /// Slice 3.5 of ADR 0007 — given a variable-declarator's `init`
    /// expression, try to compute the precise shape of the call
    /// result by substituting each callee `return_shape` with the
    /// caller's shape for the matching argument.
    ///
    /// Returns `None` if the init isn't a recognised call shape, the
    /// callee summary isn't resolvable, or no caller arg has a
    /// known local shape. Returns `Some(canonical_cell)` otherwise.
    /// The returned shape is what the caller should record under
    /// the local binding.
    fn compute_call_return_shape(&self, init: &Expression<'_>) -> Option<Cell> {
        let inner = match init {
            Expression::AwaitExpression(aw) => &aw.argument,
            Expression::ParenthesizedExpression(p) => &p.expression,
            _ => init,
        };
        let call = match inner {
            Expression::CallExpression(c) => c.as_ref(),
            _ => return None,
        };
        let summary = self.lookup_callee_summary(&call.callee)?;
        let mut result = Cell::bot();
        let mut any_contribution = false;
        for (i, arg) in call.arguments.iter().enumerate() {
            let Some(arg_expr) = argument_expr(arg) else {
                continue;
            };
            let Some(callee_param) = summary.params.get(i) else {
                continue;
            };
            let Some(callee_return) = &callee_param.return_shape else {
                continue;
            };
            let Some(caller_arg_shape) = self.expr_to_cell(arg_expr) else {
                continue;
            };
            let mut instantiated = callee_return.clone();
            instantiated.instantiate_tainted(&caller_arg_shape);
            result.merge_into(&instantiated);
            any_contribution = true;
        }
        if !any_contribution {
            return None;
        }
        result.canonicalize()
    }

    /// Best-effort projection of an expression to a [`Cell`] that
    /// represents what the caller knows about it. Slice 3.5
    /// substrate for cross-file return-shape propagation. Bare
    /// tainted idents return their `local_shape`; trivial wrappers
    /// pass through; everything else (chains, calls, complex
    /// exprs) returns `None` for now — extending coverage is a
    /// future slice.
    fn expr_to_cell(&self, expr: &Expression<'_>) -> Option<Cell> {
        match expr {
            Expression::ParenthesizedExpression(p) => self.expr_to_cell(&p.expression),
            Expression::TSAsExpression(t) => self.expr_to_cell(&t.expression),
            Expression::TSNonNullExpression(t) => self.expr_to_cell(&t.expression),
            Expression::TSSatisfiesExpression(t) => self.expr_to_cell(&t.expression),
            Expression::TSTypeAssertion(t) => self.expr_to_cell(&t.expression),
            Expression::Identifier(id) => self.local_shape(id.name.as_str()).cloned(),
            _ => None,
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
                // Slice 8.3a of ADR 0008 — registry-dispatched sanitiser
                // recognition. Other call sites of is_sanitizer_call in
                // this file stay on the legacy path until later slices
                // migrate them; debug-assert parallel check verifies the
                // registry agrees with the legacy predicate.
                let registry_sanitizes = self.registry_as_sanitizer(call);
                #[cfg(debug_assertions)]
                {
                    let legacy = is_sanitizer_call(call);
                    debug_assert_eq!(
                        registry_sanitizes, legacy,
                        "ParserSanitizer registry diverged from legacy at call {:?}",
                        call.span,
                    );
                }
                if registry_sanitizes {
                    // Still walk arguments to record any nested sinks/taint.
                    for arg in &call.arguments {
                        if let Some(e) = argument_expr(arg) {
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
                        if let Some(e) = argument_expr(arg) {
                            let _ = self.expr_taint(e);
                            self.scan_for_sinks(e);
                        }
                    }
                    return false;
                }
                // A request-body source call returns tainted data.
                // Slice 8.2 of ADR 0008 — registry-dispatched source
                // recognition. The legacy `matches_body_call` path
                // continues to serve other call sites in this file
                // until later slices migrate them; the parallel-
                // assertion below verifies the registry doesn't
                // diverge from the legacy predicate in debug builds.
                let registry_source = self.registry_as_source(expr);
                #[cfg(debug_assertions)]
                {
                    let legacy = self.matches_body_call(call);
                    debug_assert_eq!(
                        registry_source.is_some(),
                        legacy,
                        "BodySource registry diverged from legacy at call {:?}",
                        call.span,
                    );
                }
                if registry_source.is_some() {
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
                    let Some(e) = argument_expr(arg) else {
                        continue;
                    };
                    if self.expr_taint(e) && self.callee_propagates_arg(summary, i) {
                        any_tainted = true;
                    }
                }
                any_tainted
            }

            Expression::StaticMemberExpression(m) => {
                // `req.body` / `request.body` are body sources.
                // Slice 8.2 of ADR 0008 — registry-dispatched
                // source recognition, with debug-assert parallel-
                // check against the legacy `matches_body_member`
                // predicate.
                let registry_source = self.registry_as_source(expr);
                #[cfg(debug_assertions)]
                {
                    let legacy = self.matches_body_member(&m.object, m.property.name.as_str());
                    debug_assert_eq!(
                        registry_source.is_some(),
                        legacy,
                        "BodySource registry diverged from legacy at member {:?}",
                        m.span,
                    );
                }
                if registry_source.is_some() {
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
                if let Some(name) = assignment_target_name(&a.left) {
                    if r {
                        self.taint(name);
                    } else if let Some(scope) = self.current_scope_mut() {
                        // Reassignment to a clean RHS clears prior taint on
                        // the binding — `let x = body; x = "safe"` should
                        // make `x` clean for the rest of the scope.
                        scope.remove(&name);
                    }
                }
                r
            }

            Expression::TSAsExpression(t) => self.expr_taint(&t.expression),
            Expression::TSNonNullExpression(t) => self.expr_taint(&t.expression),
            Expression::TSSatisfiesExpression(t) => self.expr_taint(&t.expression),
            Expression::TSTypeAssertion(t) => self.expr_taint(&t.expression),

            // Optional chaining: `body?.x()` — for taint we treat it
            // identically to a non-optional chain. The `undefined` short-
            // circuit doesn't add or strip taint.
            Expression::ChainExpression(c) => self.chain_element_taint(&c.expression),

            // Tagged template: `sql`...${tainted}...`` — the tag function
            // could be a SQL builder etc. Conservatively, taint
            // propagates if any interpolated expression is tainted.
            Expression::TaggedTemplateExpression(t) => {
                let mut tainted = false;
                for e in &t.quasi.expressions {
                    if self.expr_taint(e) {
                        tainted = true;
                    }
                }
                tainted
            }

            _ => false,
        }
    }

    fn chain_element_taint(&mut self, el: &ChainElement<'_>) -> bool {
        match el {
            ChainElement::CallExpression(call) => {
                // Mirror the standard CallExpression branch — sanitisers,
                // db-reads, body sources, then conservative propagation.
                if is_sanitizer_call(call) || is_db_read_call(call) {
                    return false;
                }
                if self.matches_body_call(call) {
                    return true;
                }
                let summary = self.lookup_callee_summary(&call.callee);
                let mut any_tainted = false;
                for (i, arg) in call.arguments.iter().enumerate() {
                    let Some(e) = argument_expr(arg) else {
                        continue;
                    };
                    if self.expr_taint(e) && self.callee_propagates_arg(summary, i) {
                        any_tainted = true;
                    }
                }
                any_tainted
            }
            ChainElement::TSNonNullExpression(t) => self.expr_taint(&t.expression),
            ChainElement::StaticMemberExpression(m) => {
                if self.matches_body_member(&m.object, m.property.name.as_str()) {
                    return true;
                }
                self.expr_taint(&m.object)
            }
            ChainElement::ComputedMemberExpression(m) => self.expr_taint(&m.object),
            ChainElement::PrivateFieldExpression(m) => self.expr_taint(&m.object),
        }
    }

    /// Classify *how* the tainted value flows into a DB write call, then
    /// emit a finding at the appropriate severity. Splitting the verdict
    /// matters because:
    ///
    /// - `prisma.X.update({ where: { email }, data: { lockedAt: null } })`
    ///   uses `email` as a primary-key lookup. The `data` block is
    ///   hardcoded; no untrusted content reaches storage. Worth
    ///   surfacing (still wrong to skip schema validation), but lower
    ///   priority than a real content write — emit at `Medium`.
    /// - `prisma.X.update({ where: {...}, data: { ...body } })` writes
    ///   untrusted content into the row. This is the original failure
    ///   mode the rule was built for — emit at `High`.
    ///
    /// For drizzle / TypeORM / Mongoose sinks, the whole call argument
    /// is content (no `where`/`data` split), so we always emit `High`
    /// when any argument is tainted.
    fn emit_db_sink_finding(&mut self, call: &CallExpression<'_>) {
        let (severity, where_only) = self.classify_db_sink_taint(call);
        let Some(severity) = severity else {
            return;
        };
        // Record taint observations into `param_shape_seen` (slice
        // 2.1c onwards). The legacy `tainted_offsets` and the
        // boolean `reaches_db_sink_unsanitized` are derived from
        // the canonicalized shape at summary time (slice 2.5).
        for arg in &call.arguments {
            if let Some(e) = argument_expr(arg) {
                self.record_taint_in_arg(e);
            }
        }
        let callee_label = callee_chain(&call.callee).unwrap_or_else(|| "db sink".into());
        let (message, help) = if where_only {
            (
                format!(
                    "Untrusted request body reaches `{callee_label}` as a `where` lookup key without validation.",
                ),
                "The body field is used as a primary-key filter, not stored content — but a schema check still rules out type-confusion attacks against the lookup.",
            )
        } else {
            (
                format!(
                    "Untrusted request body reaches `{callee_label}` without a validating parser along the path.",
                ),
                "Validate the body with zod/valibot/yup before passing it to the DB write.",
            )
        };
        self.findings.push(
            Finding::ast(RULE_ID, severity, message, to_span(&self.file, call.span))
                .with_help(help),
        );
    }

    /// Walk a sink-call argument expression and record taint
    /// observations into `param_shape_seen`. Recurses through
    /// structural shapes (object/array literals, spreads, casts) but
    /// not through call expressions — propagation through callees is
    /// handled at the cross-file site via shape merge.
    ///
    /// `body` records `Tainted+Bot` (whole-value taint at root).
    /// `body.id` records `Obj{id: Tainted+Bot}` (single-field chain).
    /// `body.where.id` records `Obj{where: Obj{id: Tainted+Bot}}`
    /// (full chain). Computed access with a literal key matches as
    /// `Field`/`Index`; non-literal collapses to `Any`.
    ///
    /// Slice 2.5: shape is the single source of truth; the legacy
    /// `tainted_offsets` and `reaches_db_sink_unsanitized` fields on
    /// `ParamFlow` are derived from the canonicalized shape at
    /// summary time.
    ///
    /// Bare-ident consumer (slice 3.5 cont'd): when the chain
    /// resolves to a bare tainted local, prefer the local's stored
    /// `Cell` (set by `taint_with_shape` from `compute_call_return_shape`)
    /// over a flat `Tainted+Bot`. This is what carries field info
    /// from `const id = pickId(body); sink(id)` into the caller's
    /// `param_shape` — without it, the chain collapses to whole-value
    /// taint at the sink site even though slice 3.5 already knows
    /// the precise shape.
    fn record_taint_in_arg(&mut self, expr: &Expression<'_>) {
        if let Some(chain) = self.full_chain(expr) {
            if chain.is_empty()
                && let Some(cell) = self.expr_to_cell(expr)
                && !matches!(cell.shape, Shape::Bot)
            {
                insert_shape_at_path(&mut self.param_shape_seen, &chain, &cell);
                return;
            }
            insert_tainted_at_path(
                &mut self.param_shape_seen,
                &chain,
                vec![TaintLabel::UserInput],
            );
            return;
        }
        match expr {
            Expression::ObjectExpression(obj) => {
                for prop in &obj.properties {
                    match prop {
                        ObjectPropertyKind::ObjectProperty(p) => {
                            self.record_taint_in_arg(&p.value);
                        }
                        ObjectPropertyKind::SpreadProperty(s) => {
                            self.record_taint_in_arg(&s.argument);
                        }
                    }
                }
            }
            Expression::ArrayExpression(arr) => {
                for el in &arr.elements {
                    if let Some(e) = el.as_expression() {
                        self.record_taint_in_arg(e);
                    }
                }
            }
            Expression::ParenthesizedExpression(p) => self.record_taint_in_arg(&p.expression),
            Expression::TSAsExpression(t) => self.record_taint_in_arg(&t.expression),
            Expression::TSNonNullExpression(t) => self.record_taint_in_arg(&t.expression),
            Expression::TSSatisfiesExpression(t) => self.record_taint_in_arg(&t.expression),
            Expression::TSTypeAssertion(t) => self.record_taint_in_arg(&t.expression),
            Expression::ConditionalExpression(c) => {
                self.record_taint_in_arg(&c.consequent);
                self.record_taint_in_arg(&c.alternate);
            }
            Expression::LogicalExpression(b) => {
                self.record_taint_in_arg(&b.left);
                self.record_taint_in_arg(&b.right);
            }
            // Conservative fallback: the expression doesn't fit any
            // structural pattern we can map onto the offset lattice
            // (most commonly a `CallExpression` whose result carries
            // taint via callee-summary propagation, e.g.
            // `getOptionalSession(mapRequestToContextForCookie(c))`).
            // If `expr_is_tainted_readonly` still says it's tainted,
            // record whole-value root taint so `param_shape_seen`
            // stays consistent with the finding-emission path.
            //
            // This preserves the slice 2.5 invariant
            // `reaches == !findings.is_empty()` — without it, a
            // cross-file sink call that wraps the tainted argument
            // through another call fires a finding but leaves the
            // shape empty (witnessed on documenso's `getSession`
            // helper during real-world OSS validation).
            //
            // The recording is intentionally root-taint (`&[]`), not
            // an attempt to model the wrapped callee's return shape:
            // precise return-shape composition happens at variable
            // bindings via `compute_call_return_shape` (ADR 0007
            // slice 3.5); at a sink site we don't have a binding to
            // attach the substituted shape to, so the safe lower
            // bound is "the parameter, at root, reaches the sink".
            other => {
                if self.expr_is_tainted_readonly(other) {
                    insert_tainted_at_path(
                        &mut self.param_shape_seen,
                        &[],
                        vec![TaintLabel::UserInput],
                    );
                }
            }
        }
    }

    /// Walk a return-statement argument expression and record taint
    /// observations into `return_shape_seen`. Slice 3.1 of ADR 0007 —
    /// mirrors `record_taint_in_arg` but drives the return-shape tree
    /// instead of the param-shape tree. Recurses through structural
    /// shapes (object/array literals, spreads, casts, ternaries,
    /// logical exprs) but not through call expressions — return-shape
    /// composition through callees lands in slice 3.5.
    ///
    /// `return body` records `Tainted+Bot` (whole-value flows out).
    /// `return body.id` records `Obj{id: Tainted+Bot}`.
    /// `return {id: body.id}` records the same shape — the
    /// limitation is documented in ADR 0007, future slices refine.
    ///
    /// Bare-ident consumer: `return id` where `id` carries a slice-3.5
    /// shape (e.g. `Obj{id: Tainted+Bot}` from `const id = pickId(b)`)
    /// merges that shape into `return_shape_seen`. This mirrors the
    /// param-side bare-ident wiring — without it, helpers that
    /// delegate to a chain helper would lose all field info on the
    /// return path even though the local already knows it.
    fn record_taint_in_return(&mut self, expr: &Expression<'_>) {
        if let Some(chain) = self.full_chain(expr) {
            if chain.is_empty()
                && let Some(cell) = self.expr_to_cell(expr)
                && !matches!(cell.shape, Shape::Bot)
            {
                insert_shape_at_path(&mut self.return_shape_seen, &chain, &cell);
                return;
            }
            insert_tainted_at_path(
                &mut self.return_shape_seen,
                &chain,
                vec![TaintLabel::UserInput],
            );
            return;
        }
        match expr {
            Expression::ObjectExpression(obj) => {
                for prop in &obj.properties {
                    match prop {
                        ObjectPropertyKind::ObjectProperty(p) => {
                            self.record_taint_in_return(&p.value);
                        }
                        ObjectPropertyKind::SpreadProperty(s) => {
                            self.record_taint_in_return(&s.argument);
                        }
                    }
                }
            }
            Expression::ArrayExpression(arr) => {
                for el in &arr.elements {
                    if let Some(e) = el.as_expression() {
                        self.record_taint_in_return(e);
                    }
                }
            }
            Expression::ParenthesizedExpression(p) => self.record_taint_in_return(&p.expression),
            Expression::TSAsExpression(t) => self.record_taint_in_return(&t.expression),
            Expression::TSNonNullExpression(t) => self.record_taint_in_return(&t.expression),
            Expression::TSSatisfiesExpression(t) => self.record_taint_in_return(&t.expression),
            Expression::TSTypeAssertion(t) => self.record_taint_in_return(&t.expression),
            Expression::ConditionalExpression(c) => {
                self.record_taint_in_return(&c.consequent);
                self.record_taint_in_return(&c.alternate);
            }
            Expression::LogicalExpression(b) => {
                self.record_taint_in_return(&b.left);
                self.record_taint_in_return(&b.right);
            }
            _ => {}
        }
    }

    /// If `expr` is a member-chain rooted in a tainted ident, return
    /// the *full* offset chain (from base to leaf). `body.where.id`
    /// returns `Some([Field("where"), Field("id")])`. Bare tainted
    /// ident returns `Some(vec![])` (the empty chain — whole-value
    /// taint). Non-tainted or non-member returns `None`.
    fn full_chain(&self, expr: &Expression<'_>) -> Option<Vec<Offset>> {
        match expr {
            Expression::ParenthesizedExpression(p) => self.full_chain(&p.expression),
            Expression::TSAsExpression(t) => self.full_chain(&t.expression),
            Expression::TSNonNullExpression(t) => self.full_chain(&t.expression),
            Expression::TSSatisfiesExpression(t) => self.full_chain(&t.expression),
            Expression::TSTypeAssertion(t) => self.full_chain(&t.expression),
            Expression::Identifier(id) if self.is_tainted(id.name.as_str()) => Some(Vec::new()),
            Expression::StaticMemberExpression(m) => {
                let mut chain = self.full_chain(&m.object)?;
                chain.push(Offset::Field(m.property.name.to_string()));
                Some(chain)
            }
            Expression::ComputedMemberExpression(m) => {
                let mut chain = self.full_chain(&m.object)?;
                chain.push(literal_offset_or_any(&m.expression));
                Some(chain)
            }
            _ => None,
        }
    }

    /// Returns `(Some(severity), where_only)` if the call has tainted
    /// arguments, `(None, _)` if it doesn't fire. `where_only` is true
    /// when the only tainted property of a Prisma write argument is
    /// under a `where` key.
    fn classify_db_sink_taint(&self, call: &CallExpression<'_>) -> (Option<Severity>, bool) {
        let any_tainted = call.arguments.iter().any(|arg| {
            argument_expr(arg)
                .map(|e| self.expr_is_tainted_readonly(e))
                .unwrap_or(false)
        });
        if !any_tainted {
            return (None, false);
        }
        // Only Prisma writes get the where-vs-data split — drizzle and
        // TypeORM-shape sinks pass the content directly as the call arg.
        if !is_prisma_write_sink(call) {
            return (Some(Severity::High), false);
        }
        let Some(first) = call.arguments.first().and_then(argument_expr) else {
            return (Some(Severity::High), false);
        };
        let obj = match first {
            Expression::ObjectExpression(o) => o,
            _ => return (Some(Severity::High), false),
        };
        let mut where_tainted = false;
        let mut content_tainted = false;
        for prop in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(p) = prop else {
                // Spread (`{ ...body }`) bypasses the where/data split —
                // treat as content-tainted to be safe.
                if let ObjectPropertyKind::SpreadProperty(s) = prop
                    && self.expr_is_tainted_readonly(&s.argument)
                {
                    content_tainted = true;
                }
                continue;
            };
            let key = match &p.key {
                PropertyKey::StaticIdentifier(id) => id.name.as_str(),
                _ => continue,
            };
            if !self.expr_is_tainted_readonly(&p.value) {
                continue;
            }
            match key {
                "where" => where_tainted = true,
                "data" | "create" | "update" => content_tainted = true,
                _ => content_tainted = true,
            }
        }
        match (where_tainted, content_tainted) {
            (true, false) => (Some(Severity::Medium), true),
            _ => (Some(Severity::High), false),
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

                // Slice 8.4 of ADR 0008 — registry-dispatched sink
                // recognition. Other call sites of is_db_write_sink
                // in this file stay on the legacy path until later
                // slices migrate them; debug-assert parallel check
                // verifies the registry agrees with the legacy
                // predicate.
                let registry_sink = self.registry_as_sink(call);
                #[cfg(debug_assertions)]
                {
                    let legacy = is_db_write_sink(call);
                    debug_assert_eq!(
                        registry_sink.is_some(),
                        legacy,
                        "DB write sink registry diverged from legacy at call {:?}",
                        call.span,
                    );
                }
                if registry_sink.is_some() {
                    self.emit_db_sink_finding(call);
                }
                // Recurse into callee + args to catch nested sinks.
                self.scan_for_sinks(&call.callee);
                for arg in &call.arguments {
                    if let Some(e) = argument_expr(arg) {
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
            Expression::ChainExpression(c) => match &c.expression {
                ChainElement::CallExpression(call) => {
                    self.check_cross_file_call(call);
                    if is_db_write_sink(call) {
                        self.emit_db_sink_finding(call);
                    }
                    self.scan_for_sinks(&call.callee);
                    for arg in &call.arguments {
                        if let Some(e) = argument_expr(arg) {
                            self.scan_for_sinks(e);
                        }
                    }
                }
                ChainElement::TSNonNullExpression(t) => self.scan_for_sinks(&t.expression),
                ChainElement::StaticMemberExpression(m) => self.scan_for_sinks(&m.object),
                ChainElement::ComputedMemberExpression(m) => {
                    self.scan_for_sinks(&m.object);
                    self.scan_for_sinks(&m.expression);
                }
                ChainElement::PrivateFieldExpression(m) => self.scan_for_sinks(&m.object),
            },
            Expression::TaggedTemplateExpression(t) => {
                self.scan_for_sinks(&t.tag);
                for e in &t.quasi.expressions {
                    self.scan_for_sinks(e);
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
                if self.matches_body_member(&m.object, m.property.name.as_str()) {
                    return true;
                }
                self.expr_is_tainted_readonly(&m.object)
            }
            Expression::ComputedMemberExpression(m) => self.expr_is_tainted_readonly(&m.object),
            Expression::CallExpression(call) => {
                if is_sanitizer_call(call) || is_db_read_call(call) {
                    return false;
                }
                if self.matches_body_call(call) {
                    return true;
                }
                let summary = self.lookup_callee_summary(&call.callee);
                call.arguments.iter().enumerate().any(|(i, arg)| {
                    argument_expr(arg)
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
            Expression::TemplateLiteral(t) => t
                .expressions
                .iter()
                .any(|e| self.expr_is_tainted_readonly(e)),
            Expression::ConditionalExpression(c) => {
                self.expr_is_tainted_readonly(&c.consequent)
                    || self.expr_is_tainted_readonly(&c.alternate)
            }
            Expression::LogicalExpression(b) => {
                self.expr_is_tainted_readonly(&b.left) || self.expr_is_tainted_readonly(&b.right)
            }
            Expression::TSAsExpression(t) => self.expr_is_tainted_readonly(&t.expression),
            Expression::TSNonNullExpression(t) => self.expr_is_tainted_readonly(&t.expression),
            Expression::TSSatisfiesExpression(t) => self.expr_is_tainted_readonly(&t.expression),
            Expression::TSTypeAssertion(t) => self.expr_is_tainted_readonly(&t.expression),
            Expression::ChainExpression(c) => match &c.expression {
                ChainElement::CallExpression(call) => {
                    if is_sanitizer_call(call) || is_db_read_call(call) {
                        return false;
                    }
                    if self.matches_body_call(call) {
                        return true;
                    }
                    let summary = self.lookup_callee_summary(&call.callee);
                    call.arguments.iter().enumerate().any(|(i, arg)| {
                        argument_expr(arg)
                            .map(|e| {
                                self.expr_is_tainted_readonly(e)
                                    && self.callee_propagates_arg(summary, i)
                            })
                            .unwrap_or(false)
                    })
                }
                ChainElement::TSNonNullExpression(t) => {
                    self.expr_is_tainted_readonly(&t.expression)
                }
                ChainElement::StaticMemberExpression(m) => {
                    if self.matches_body_member(&m.object, m.property.name.as_str()) {
                        return true;
                    }
                    self.expr_is_tainted_readonly(&m.object)
                }
                ChainElement::ComputedMemberExpression(m) => {
                    self.expr_is_tainted_readonly(&m.object)
                }
                ChainElement::PrivateFieldExpression(m) => self.expr_is_tainted_readonly(&m.object),
            },
            Expression::TaggedTemplateExpression(t) => t
                .quasi
                .expressions
                .iter()
                .any(|e| self.expr_is_tainted_readonly(e)),
            _ => false,
        }
    }
}

impl<'a, 'idx> Visit<'a> for FlowVisitor<'idx> {
    fn visit_variable_declarator(&mut self, decl: &stryx_ast::ast::VariableDeclarator<'a>) {
        // Capture the binding name so the next visit_arrow / visit_function
        // can recover its effective name. `const handler = async (req) => {}`
        // has no `Function::id`, but the surrounding declarator does.
        let prev = self.pending_binding_name.take();
        if let BindingPattern::BindingIdentifier(id) = &decl.id {
            self.pending_binding_name = Some(id.name.to_string());
        }
        stryx_ast::walk::walk_variable_declarator(self, decl);
        self.pending_binding_name = prev;
    }

    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        let name = func
            .id
            .as_ref()
            .map(|id| id.name.to_string())
            .or_else(|| self.pending_binding_name.clone());
        let suppress = name
            .as_deref()
            .is_some_and(|n| self.body_validated_handlers.contains(n));
        if suppress {
            self.body_source_suppressed += 1;
        }
        self.enter_fn();
        // NestJS and similar frameworks declare body sources via parameter
        // decorators (`@Body() dto: CreateUserDto`). Pre-taint any param
        // marked with one — the framework will inject body data there.
        // Skip when the enclosing wrapper has already validated the body.
        if self.body_source_active() {
            for pname in body_decorated_param_names(&func.params) {
                self.taint(pname);
            }
        }
        if let Some(body) = &func.body {
            self.handle_function_body(&body.statements);
        }
        self.exit_fn();
        if suppress {
            self.body_source_suppressed -= 1;
        }
        let _ = flags;
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        let suppress = self
            .pending_binding_name
            .as_deref()
            .is_some_and(|n| self.body_validated_handlers.contains(n));
        if suppress {
            self.body_source_suppressed += 1;
        }
        self.enter_fn();
        // Arrow body is always a FunctionBody; its `statements` contains the
        // expression-bodied case wrapped as a single ExpressionStatement.
        self.handle_function_body(&arrow.body.statements);
        self.exit_fn();
        if suppress {
            self.body_source_suppressed -= 1;
        }
    }

    fn visit_class(&mut self, class: &Class<'a>) {
        let pushed = if let Some(id) = &class.id {
            self.class_stack.push(id.name.to_string());
            true
        } else {
            false
        };
        stryx_ast::walk::walk_class(self, class);
        if pushed {
            self.class_stack.pop();
        }
    }
}

impl FlowVisitor<'_> {
    /// Slice 2: when a tainted argument is passed to a call site whose
    /// callee resolves through the project index to a function that
    /// taints that parameter to a sink, emit a cross-file finding.
    /// Handles both bare-identifier calls (`createUser(body)`) and
    /// `this.<member>.<method>(body)` calls in NestJS-shaped code.
    fn check_cross_file_call(&mut self, call: &CallExpression<'_>) {
        let Some(summary) = self.lookup_callee_summary(&call.callee) else {
            return;
        };
        let callee_label = callee_chain(&call.callee).unwrap_or_else(|| "<call>".to_string());
        for (i, arg) in call.arguments.iter().enumerate() {
            let Some(arg_expr) = argument_expr(arg) else {
                continue;
            };
            if !self.expr_is_tainted_readonly(arg_expr) {
                continue;
            }
            if !summary.taints_through_param(i) {
                continue;
            }
            // Slice 2.1c+ — record taint at the cross-file site
            // into `param_shape_seen`. Captures `helper(body.user)`
            // where the caller's chain on its tainted ident is
            // `Field("user")` even though the sink lives in another
            // file. (Slice 3c's separate `tainted_offsets` absorb
            // was retired in slice 2.5 — the shape merge below
            // captures the same information end-to-end.)
            self.record_taint_in_arg(arg_expr);
            // Slice 2.1d — compose callee's full param_shape into
            // the caller's shape tree at the caller's offset chain.
            // `full_chain` returns Some(vec![]) for bare ident, and
            // `insert_shape_at_path` reduces to a root-merge in
            // that case — the bare-ident absorption is the same
            // operation, generalised to handle chain args too.
            if let Some(chain) = self.full_chain(arg_expr)
                && let Some(callee_param) = summary.params.get(i)
                && let Some(callee_shape) = &callee_param.param_shape
            {
                insert_shape_at_path(&mut self.param_shape_seen, &chain, callee_shape);
            }
            let sink_hint = summary
                .params
                .get(i)
                .and_then(|p| p.sink_span.as_ref())
                .map(|s| format!(" The sink lives in {}.", s.file.display()))
                .unwrap_or_default();
            // Slice 2.2 of ADR 0006 — when the callee's `param_shape`
            // reveals specific top-level fields, surface them in the
            // finding so the user sees *which* parts of the body flow.
            // Whole-value flow (Tainted+Bot) yields no field list, so
            // the parenthetical stays the way slice 3c emitted it.
            let fields_hint = summary
                .params
                .get(i)
                .and_then(|p| p.param_shape.as_ref())
                .and_then(top_level_field_names)
                .map(|names| {
                    let quoted: Vec<String> = names.iter().map(|n| format!("`{n}`")).collect();
                    format!(", fields: {}", quoted.join(", "))
                })
                .unwrap_or_default();
            self.findings.push(
                Finding::ast(
                    RULE_ID,
                    Severity::High,
                    format!(
                        "Untrusted request body flows into `{}` (param `{}`{fields_hint}), which writes to the database without validating it.{sink_hint}",
                        callee_label,
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
//
// `is_request_body_member`, `is_body_source_call`, and the helper
// `is_request_like_expr` moved to `crate::steps::sources::body`
// (ADR 0008 slice 8.2). Imported at the top of this file and
// dispatched via `RULE_STEPS` through `registry_as_source`.

// `is_sanitizer_call` and `second_arg_has_schema_key` moved to
// `crate::steps::sanitizers::parser` (ADR 0008 slice 8.3a). Imported
// at the top of this file; expr_taint dispatches through
// `RULE_STEPS` via `registry_as_sanitizer`.

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

// `is_db_write_sink`, `is_prisma_write_sink`, `is_drizzle_write_sink`,
// `is_orm_write_sink` moved to `crate::steps::sinks::db`
// (ADR 0008 slice 8.4). Imported at the top of this file; one call
// site in scan_for_sinks dispatches through `RULE_STEPS` via
// `registry_as_sink`.

/// Best-effort extraction of an Expression from a `ForStatementInit`
/// when it isn't a `VariableDeclaration`. Slice 1.5: only the bare
/// expression-as-init shape is recognised; complex inheritance variants
/// fall through.
fn expression_from_for_init<'a>(
    init: &'a stryx_ast::ast::ForStatementInit<'_>,
) -> Option<&'a Expression<'a>> {
    use stryx_ast::ast::ForStatementInit;
    if let ForStatementInit::VariableDeclaration(_) = init {
        return None;
    }
    // ForStatementInit inherits Expression variants; cast back via match
    // on a few common shapes. Anything else falls through and is
    // skipped — it will still be visited by the default Visit walk.
    None
}

/// Underlying expression for a call argument, peeling spread elements
/// (`...x` becomes `x` for taint-propagation purposes; the array's
/// elements all share the same taint as the array itself in our coarse
/// model).
fn argument_expr<'a>(arg: &'a Argument<'_>) -> Option<&'a Expression<'a>> {
    match arg {
        Argument::SpreadElement(s) => Some(&s.argument),
        _ => arg.as_expression(),
    }
}

/// Peel TS-cast and parenthesis wrappers off an expression, exposing
/// the underlying value. Used by offset extraction so that
/// `(body as Body).id` and `body!.id` both record `Field("id")`.
fn strip_casts<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    match expr {
        Expression::ParenthesizedExpression(p) => strip_casts(&p.expression),
        Expression::TSAsExpression(t) => strip_casts(&t.expression),
        Expression::TSNonNullExpression(t) => strip_casts(&t.expression),
        Expression::TSSatisfiesExpression(t) => strip_casts(&t.expression),
        Expression::TSTypeAssertion(t) => strip_casts(&t.expression),
        _ => expr,
    }
}

/// Mutate `cell` so that the offset chain `path` ends in a Tainted
/// leaf carrying `labels`. Empty `path` means "this whole value is
/// tainted" — the cell's own xtaint is set. Otherwise we walk down,
/// inserting `Cell::bot()` placeholders along the way and converting
/// `Shape::Bot` into an empty `Obj` when we need to descend through
/// it. Slice 2.1c of ADR 0006.
///
/// Repeated calls compose: two observations sharing a prefix
/// (`body.where.id` and `body.where.email`) will share their
/// `body.where` intermediate cell and produce two siblings under it.
/// `Cell::canonicalize` is run once at summary time to clean up.
fn insert_tainted_at_path(cell: &mut Cell, path: &[Offset], labels: Vec<TaintLabel>) {
    if path.is_empty() {
        cell.xtaint = Xtaint::Tainted(labels);
        return;
    }
    if matches!(cell.shape, Shape::Bot) {
        cell.shape = Shape::Obj(std::collections::BTreeMap::new());
    }
    if let Shape::Obj(map) = &mut cell.shape {
        let entry = map.entry(path[0].clone()).or_insert_with(Cell::bot);
        insert_tainted_at_path(entry, &path[1..], labels);
    }
}

/// Extract top-level Field names from a [`Cell`]'s shape. Slice 2.2
/// of ADR 0006 — first consumer of `param_shape`. Returns `None`
/// when the shape carries no structural information (the cell is
/// whole-value tainted or just has a non-Field offset like `Index`
/// or `Any`); returns `Some(["name", "email"])` when the shape is
/// `Obj { name: ..., email: ... }`. The returned names are
/// already in `BTreeMap` iteration order (`Offset::Ord`), so the
/// rendered message is deterministic.
fn top_level_field_names(cell: &Cell) -> Option<Vec<String>> {
    match &cell.shape {
        Shape::Obj(map) => {
            let names: Vec<String> = map
                .keys()
                .filter_map(|off| match off {
                    Offset::Field(s) => Some(s.clone()),
                    _ => None,
                })
                .collect();
            if names.is_empty() { None } else { Some(names) }
        }
        Shape::Bot => None,
        // `Arg` is an opaque placeholder until instantiated at a
        // call site (slice 2.3b). No visible fields to surface.
        Shape::Arg(_) => None,
    }
}

/// Graft the entire `source` cell into `target` at offset chain
/// `path`. Slice 2.1d of ADR 0006 — used at the cross-file site to
/// compose a callee's parameter shape into the caller's tree.
///
/// `path = []` merges `source` into `target` directly (bare-ident
/// pass-through). `path = [user]` walks one level down, creating an
/// intermediate `Obj{user: ...}` if needed, then merges `source`
/// into that cell — this captures the case where the caller passes
/// `body.user` to a helper whose summary describes shape rooted at
/// the helper's parameter.
fn insert_shape_at_path(target: &mut Cell, path: &[Offset], source: &Cell) {
    if path.is_empty() {
        target.merge_into(source);
        return;
    }
    if matches!(target.shape, Shape::Bot) {
        target.shape = Shape::Obj(std::collections::BTreeMap::new());
    }
    if let Shape::Obj(map) = &mut target.shape {
        let entry = map.entry(path[0].clone()).or_insert_with(Cell::bot);
        insert_shape_at_path(entry, &path[1..], source);
    }
}

/// Stable ordering for offsets so serialised summaries are
/// deterministic across runs (the cache-key contract from ADR 0005
/// requires it).
fn offset_sort_key(a: &Offset, b: &Offset) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a, b) {
        (Offset::Field(x), Offset::Field(y)) => x.cmp(y),
        (Offset::Index(x), Offset::Index(y)) => x.cmp(y),
        (Offset::Any, Offset::Any) => Ordering::Equal,
        (Offset::Field(_), _) => Ordering::Less,
        (_, Offset::Field(_)) => Ordering::Greater,
        (Offset::Index(_), Offset::Any) => Ordering::Less,
        (Offset::Any, Offset::Index(_)) => Ordering::Greater,
    }
}

/// Best-effort offset extraction from a computed-member key. Literal
/// numeric / string keys record as `Index` / `Field`; anything else
/// collapses to `Any` (the wildcard that Phase 2's shape lattice
/// handles natively as `Oany`).
fn literal_offset_or_any(expr: &Expression<'_>) -> Offset {
    match strip_casts(expr) {
        Expression::NumericLiteral(n) => {
            let v = n.value;
            if v.is_finite() && v >= 0.0 && v <= u32::MAX as f64 && v.fract() == 0.0 {
                Offset::Index(v as u32)
            } else {
                Offset::Any
            }
        }
        Expression::StringLiteral(s) => Offset::Field(s.value.to_string()),
        _ => Offset::Any,
    }
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

/// Collect identifiers narrowed by an early-return guard. Walks
/// OR-chains and accepts each clause that:
///
/// - is `!ARR.includes(IDENT)` — allow-list narrowing
/// - is `typeof IDENT !== "<lit>"` (or `==`/`===`/`!==` against a
///   type-string literal) — type-name narrowing
///
/// In both cases the variable is provably constrained past the guard,
/// so we clear its taint.
fn collect_includes_narrowed(
    test: &Expression<'_>,
    allow_lists: &HashSet<String>,
    out: &mut Vec<String>,
) {
    match test {
        Expression::LogicalExpression(b) if b.operator == LogicalOperator::Or => {
            collect_includes_narrowed(&b.left, allow_lists, out);
            collect_includes_narrowed(&b.right, allow_lists, out);
        }
        _ => {
            if let Some(name) = match_includes_negation(test, allow_lists) {
                out.push(name.to_string());
            } else if let Some(name) = match_typeof_check(test) {
                out.push(name.to_string());
            }
        }
    }
}

/// `typeof X !== "string"` (or `==`, `===`, `!==`) — for an early-return
/// guard, this proves X has a known runtime type past the guard. Treat
/// any of these forms as taint-clearing for the named identifier.
fn match_typeof_check<'a>(expr: &'a Expression<'_>) -> Option<&'a str> {
    let Expression::BinaryExpression(b) = expr else {
        return None;
    };
    if !matches!(
        b.operator,
        BinaryOperator::Equality
            | BinaryOperator::Inequality
            | BinaryOperator::StrictEquality
            | BinaryOperator::StrictInequality,
    ) {
        return None;
    }
    // Either side may be the typeof; the other should be a string literal.
    let (typeof_side, lit_side) = match (&b.left, &b.right) {
        (Expression::UnaryExpression(_), other) => (&b.left, other),
        (other, Expression::UnaryExpression(_)) => (&b.right, other),
        _ => return None,
    };
    let Expression::UnaryExpression(unary) = typeof_side else {
        return None;
    };
    if unary.operator != UnaryOperator::Typeof {
        return None;
    }
    let Expression::Identifier(id) = &unary.argument else {
        return None;
    };
    // Other side must be a string literal — `"string"`, `"number"`, etc.
    if !matches!(lit_side, Expression::StringLiteral(_)) {
        return None;
    }
    Some(id.name.as_str())
}

fn match_includes_negation<'a>(
    expr: &'a Expression<'_>,
    allow_lists: &HashSet<String>,
) -> Option<&'a str> {
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
    // Receiver: either a literal array or an Identifier that names a
    // top-level allow-list `const`.
    let receiver_ok = match &method.object {
        Expression::ArrayExpression(_) => true,
        Expression::Identifier(id) => allow_lists.contains(id.name.as_str()),
        _ => false,
    };
    if !receiver_ok {
        return None;
    }
    if call.arguments.len() != 1 {
        return None;
    }
    let arg_expr = argument_expr(&call.arguments[0])?;
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
                collect_named_re_exports(decl, &mut summary);
            }
            Statement::ExportAllDeclaration(decl) => {
                summary
                    .wildcard_re_exports
                    .push(decl.source.value.to_string());
            }
            Statement::ExportDefaultDeclaration(decl) => {
                collect_default_export(&file, &decl.declaration, index, &mut summary);
            }
            Statement::ClassDeclaration(class) => {
                collect_class(&file, class, index, &mut summary);
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
                        None,
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
                    let Some(init) = &declarator.init else {
                        continue;
                    };
                    if let Some(s) = summarise_initialiser(&file, &name, init, index) {
                        summary.locals.insert(name, s);
                    }
                }
            }
            _ => {}
        }
    }

    // Second pass: detect `export default <wrapper>(<inner>)` and
    // `export const X = <wrapper>(<inner>)` patterns where <wrapper>
    // resolves to a same-file function whose body validates
    // `req.body`. The <inner> handler's body taint is suppressed at
    // run time. Cross-file wrappers are handled in slice 2.
    for stmt in &program.body {
        if let Some(inner) = wrap_at_export_inner(stmt, &summary) {
            summary.body_validated_handlers.insert(inner);
        }
    }

    summary
}

/// Detects `export default <wrapper>(<inner>)` and
/// `export const _ = <wrapper>(<inner>)` patterns. Returns the inner
/// handler's local name when the wrapper is a same-file function
/// whose body validates `req.body`.
fn wrap_at_export_inner(stmt: &Statement<'_>, summary: &FileSummary) -> Option<String> {
    let call = match stmt {
        Statement::ExportDefaultDeclaration(decl) => match &decl.declaration {
            ExportDefaultDeclarationKind::CallExpression(c) => c,
            _ => return None,
        },
        Statement::ExportNamedDeclaration(decl) => match decl.declaration.as_ref()? {
            Declaration::VariableDeclaration(var) => {
                let declarator = var.declarations.first()?;
                match &declarator.init {
                    Some(Expression::CallExpression(c)) => c,
                    _ => return None,
                }
            }
            _ => return None,
        },
        _ => return None,
    };
    let Expression::Identifier(wrapper_id) = &call.callee else {
        return None;
    };
    let wrapper_name = wrapper_id.name.as_str();
    let wrapper_summary = summary
        .exports
        .get(wrapper_name)
        .or_else(|| summary.locals.get(wrapper_name))?;
    if !wrapper_summary.validates_request_body {
        return None;
    }
    // The inner handler is the wrapper's first argument, expected to
    // be a bare identifier referring to a local function or arrow.
    let Expression::Identifier(inner_id) = call.arguments.first()?.as_expression()? else {
        return None;
    };
    Some(inner_id.name.to_string())
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

/// `export { foo } from "./bar"` and `export { foo as baz } from "./bar"`
/// — barrel-file re-export form. Recorded so the project index can
/// chase chains of re-exports during finalize. Plain
/// `export { foo }` (no source) is not a re-export and is skipped.
fn collect_named_re_exports(decl: &ExportNamedDeclaration<'_>, summary: &mut FileSummary) {
    if matches!(decl.export_kind, ImportOrExportKind::Type) {
        return;
    }
    let Some(source) = &decl.source else {
        return;
    };
    let module = source.value.to_string();
    for spec in &decl.specifiers {
        let local_name = spec.local.name().to_string();
        let exported_name = spec.exported.name().to_string();
        summary.re_exports.insert(
            exported_name,
            ImportRef {
                module_specifier: module.clone(),
                imported_name: local_name,
            },
        );
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
                && let Some(s) =
                    summarise_function(file, &name, &func.params, func.body.as_deref(), index, None)
            {
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
                if let Some(s) = summarise_initialiser(file, &name, init, index) {
                    summary.exports.insert(name, s);
                }
            }
        }
        Declaration::ClassDeclaration(class) => {
            collect_class(file, class, index, summary);
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
            None,
        ),
        ExportDefaultDeclarationKind::ArrowFunctionExpression(arrow) => Some(summarise_arrow(
            file,
            "default",
            &arrow.params,
            &arrow.body,
            index,
        )),
        ExportDefaultDeclarationKind::ClassDeclaration(class) => {
            collect_class(file, class, index, summary);
            None
        }
        _ => None,
    };
    if let Some(s) = s {
        summary.exports.insert("default".to_string(), s);
    }
}

/// Walk a top-level class declaration, summarise each method, and
/// record constructor parameter properties + property declarations as
/// field types so `this.<member>` lookups work cross-file.
fn collect_class(
    file: &std::path::Path,
    class: &Class<'_>,
    index: Option<&stryx_index::ProjectIndex>,
    summary: &mut FileSummary,
) {
    let Some(class_name) = class.id.as_ref().map(|id| id.name.to_string()) else {
        return;
    };
    let mut info = ClassInfo::default();
    for el in &class.body.body {
        let ClassElement::MethodDefinition(method) = el else {
            // PropertyDefinition with type annotations: record as field.
            if let ClassElement::PropertyDefinition(prop) = el {
                let Some(name) = property_key_name(&prop.key) else {
                    continue;
                };
                if let Some(t) = type_annotation_name(prop.type_annotation.as_deref()) {
                    info.field_types.insert(name, t);
                }
            }
            continue;
        };
        if matches!(
            method.kind,
            MethodDefinitionKind::Constructor
                | MethodDefinitionKind::Get
                | MethodDefinitionKind::Set
        ) {
            // Constructor: harvest parameter properties as field types.
            if method.kind == MethodDefinitionKind::Constructor {
                for param in &method.value.params.items {
                    if param.accessibility.is_none() && !param.readonly {
                        continue;
                    }
                    let Some(name) = single_binding_name(&param.pattern) else {
                        continue;
                    };
                    if let Some(t) = type_annotation_name(param.type_annotation.as_deref()) {
                        info.field_types.insert(name, t);
                    }
                }
            }
            continue;
        }
        let Some(method_name) = property_key_name(&method.key) else {
            continue;
        };
        if let Some(s) = summarise_function(
            file,
            &method_name,
            &method.value.params,
            method.value.body.as_deref(),
            index,
            Some(&class_name),
        ) {
            info.methods.insert(method_name, s);
        }
    }
    summary.classes.insert(class_name, info);
}

fn property_key_name(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(id) => Some(id.name.to_string()),
        PropertyKey::StringLiteral(s) => Some(s.value.to_string()),
        _ => None,
    }
}

/// Resolve a TS type annotation to its identifier name, e.g.
/// `: UsersService` → `Some("UsersService")`. Returns `None` for
/// generic / union / inline / non-identifier types.
fn type_annotation_name(
    annotation: Option<&stryx_ast::ast::TSTypeAnnotation<'_>>,
) -> Option<String> {
    let TSType::TSTypeReference(tref) = &annotation?.type_annotation else {
        return None;
    };
    let TSTypeName::IdentifierReference(id) = &tref.type_name else {
        return None;
    };
    Some(id.name.to_string())
}

fn summarise_initialiser(
    file: &std::path::Path,
    name: &str,
    init: &Expression<'_>,
    index: Option<&stryx_index::ProjectIndex>,
) -> Option<ExportedFunctionSummary> {
    match init {
        Expression::FunctionExpression(func) => {
            summarise_function(file, name, &func.params, func.body.as_deref(), index, None)
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
    class_context: Option<&str>,
) -> Option<ExportedFunctionSummary> {
    let body_stmts = body.map(|b| b.statements.as_slice()).unwrap_or(&[]);
    Some(build_summary(
        file,
        name,
        params,
        body_stmts,
        index,
        class_context,
    ))
}

fn summarise_arrow(
    file: &std::path::Path,
    name: &str,
    params: &stryx_ast::ast::FormalParameters<'_>,
    body: &FunctionBody<'_>,
    index: Option<&stryx_index::ProjectIndex>,
) -> ExportedFunctionSummary {
    build_summary(file, name, params, &body.statements, index, None)
}

fn build_summary(
    file: &std::path::Path,
    name: &str,
    params: &stryx_ast::ast::FormalParameters<'_>,
    body: &[Statement<'_>],
    index: Option<&stryx_index::ProjectIndex>,
    class_context: Option<&str>,
) -> ExportedFunctionSummary {
    let param_names: Vec<String> = params
        .items
        .iter()
        .map(|p| single_binding_name(&p.pattern).unwrap_or_else(|| format!("_arg{}", p.span.start)))
        .collect();

    let mut params_out = Vec::with_capacity(param_names.len());
    for (idx, pname) in param_names.iter().enumerate() {
        // Run the flow visitor over the function body with just this
        // parameter pre-tainted. The visitor consults the *previous
        // iteration's* index, so cross-file calls already known to sink
        // contribute too — that's what makes summaries converge through
        // multi-level chains (controller → service → repository).
        let mut visitor = FlowVisitor::new(file.to_path_buf(), index);
        if let Some(cls) = class_context {
            visitor.class_stack.push(cls.to_string());
        }
        visitor.enter_fn();
        visitor.taint(pname.clone());
        for stmt in body {
            visitor.handle_statement(stmt);
        }
        visitor.exit_fn();

        let sink_span = visitor.findings.first().map(|f| f.span.clone());
        let propagates_to_return = visitor.tainted_return;
        // Slice 2.1c canonicalize → Some(concrete) for observed
        // params, None for un-observed.
        //
        // Slice 2.3a — when canonicalize returns None (no taint
        // observations were recorded), emit a polymorphic placeholder
        // `Arg(arg_id)` so the summary carries this parameter's
        // identity. ArgId is built from the function's stable name and
        // 0-based parameter index per ADR 0006.
        let param_shape = visitor.param_shape_seen.canonicalize().or_else(|| {
            Some(Cell::arg_placeholder(stryx_taint::ArgId {
                fn_id: name.to_string(),
                idx: idx as u32,
            }))
        });
        // Slice 2.5 — derive the legacy `tainted_offsets` and
        // `reaches_db_sink_unsanitized` fields from `param_shape`
        // (the single source of truth). Sanity-cross-checked with a
        // debug assertion against the visitor's findings list, which
        // was the previous source of truth for `reaches`.
        let reaches = param_shape.as_ref().is_some_and(Cell::has_tainted_leaf);
        debug_assert_eq!(
            reaches,
            !visitor.findings.is_empty(),
            "shape-derived reaches must match findings.is_empty(); \
             a finding-emission path is missing its record_taint_in_arg call",
        );
        let mut tainted_offsets: Vec<Offset> = param_shape
            .as_ref()
            .map(Cell::top_tainted_offsets)
            .unwrap_or_default();
        tainted_offsets.sort_by(offset_sort_key);
        // Slice 3.1 of ADR 0007 — drain the per-param simulation's
        // return-shape observations. None when no tainted return was
        // observed; some(canonical) otherwise. The boolean
        // `tainted_return` is set by `expr_taint`, which walks
        // through call expressions ("call with tainted arg ⇒
        // tainted") whereas `record_taint_in_return` only follows
        // structural shapes (object/array/casts). So a tainted-leaf
        // shape implies `tainted_return`, but not the converse:
        // `return helper(body)` with helper not yet summarised sets
        // the boolean but records no shape (cross-file return-shape
        // propagation lands in slice 3.5).
        let return_shape = visitor.return_shape_seen.canonicalize();
        debug_assert!(
            !return_shape.as_ref().is_some_and(Cell::has_tainted_leaf) || propagates_to_return,
            "return_shape has tainted leaves but tainted_return = false; \
             a return-statement path is missing its record_taint_in_return call",
        );
        params_out.push(ParamFlow {
            name: pname.clone(),
            reaches_db_sink_unsanitized: reaches,
            propagates_to_return,
            sink_span,
            tainted_offsets,
            param_shape,
            return_shape,
        });
    }

    ExportedFunctionSummary {
        name: name.to_string(),
        params: params_out,
        span: Span::new(file.to_path_buf(), params.span.start, params.span.end),
        contains_auth_check: contains_auth_helper_call(body),
        validates_request_body: body_validates_request(body),
    }
}

/// True if `body` contains a call shaped like
/// `<schema>.parse(req.body)` or `<schema>.safeParse(req.body)`. Used
/// to mark validation-wrapper functions whose presence at an export
/// site (`export default validate(handler)`) lets us treat the inner
/// handler's `req.body` as already structurally validated.
pub(crate) fn body_validates_request(body: &[Statement<'_>]) -> bool {
    let mut visitor = BodyValidationVisitor { found: false };
    for stmt in body {
        visitor.visit_statement(stmt);
        if visitor.found {
            return true;
        }
    }
    false
}

struct BodyValidationVisitor {
    found: bool,
}

impl<'a> Visit<'a> for BodyValidationVisitor {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.found {
            return;
        }
        if call_validates_request_body(call) {
            self.found = true;
            return;
        }
        stryx_ast::walk::walk_call_expression(self, call);
    }
}

fn call_validates_request_body(call: &CallExpression<'_>) -> bool {
    // `<expr>.parse(<arg>)` or `<expr>.safeParse(<arg>)` where <arg>
    // is a request-body source. The receiver expression is opaque —
    // any zod-like schema works.
    let Some(MemberExpression::StaticMemberExpression(method)) = call.callee.as_member_expression()
    else {
        return false;
    };
    if !matches!(
        method.property.name.as_str(),
        "parse" | "safeParse" | "parseAsync" | "safeParseAsync"
    ) {
        return false;
    }
    let Some(first) = call.arguments.first().and_then(argument_expr) else {
        return false;
    };
    expression_reads_request_body(first)
}

/// `req.body`, `request.body`, or an `await req.json()` / `req.text()`
/// / `req.formData()` call — anything we'd taint in expr_taint as a
/// fresh body source.
fn expression_reads_request_body(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::StaticMemberExpression(m) => {
            is_request_body_member(&m.object, m.property.name.as_str())
        }
        Expression::AwaitExpression(a) => expression_reads_request_body(&a.argument),
        Expression::ParenthesizedExpression(p) => expression_reads_request_body(&p.expression),
        Expression::CallExpression(c) => is_body_source_call(c),
        _ => false,
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
