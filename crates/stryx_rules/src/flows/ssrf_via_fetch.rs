//! `flow/ssrf-via-fetch` — slice 1 (single-file) + slice 2
//! (cross-file via ExportedFunctionSummary).
//!
//! Detects request-body-tainted values reaching an outbound HTTP
//! call (`fetch`, `axios.<method>`, `got`) as the URL argument
//! without a recognised allow-list sanitiser along the path.
//!
//! Slice 2 — cross-file. The route handler hands body data to an
//! imported helper that does the outbound HTTP call. The extract
//! pass simulates each exported function with one parameter
//! pre-tainted and records the result on
//! `ParamFlow::reaches_fetch_sink_unsanitized`; the run pass walks
//! call sites in the handler, looks up the callee via the project
//! index, and emits a finding when a tainted argument flows into a
//! reach-flagged parameter slot.
//!
//! See `docs/rules/flow-ssrf-via-fetch.md` for the rule's contract
//! and the bad/good fixtures it pins.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use stryx_ast::{
    Visit,
    ast::{
        Argument, ArrowFunctionExpression, AssignmentExpression, AssignmentTarget, BindingPattern,
        CallExpression, ChainElement, Declaration, ExportDefaultDeclarationKind, Expression,
        Function, FunctionBody, IfStatement, LogicalOperator, ObjectPropertyKind, Program,
        PropertyKey, Statement, VariableDeclarator,
    },
    to_span,
};
use stryx_core::{Finding, Severity, Span};
use stryx_index::FileSummary;
use stryx_taint::{ExportedFunctionSummary, ParamFlow};

use crate::adapters::EnabledAdapters;
use crate::flows::unvalidated_body_to_db::decorated_param_names_for_adapters;
use crate::steps::sanitizers::{
    branch_returns, extract_url_constructor_input, match_url_allow_list_guard,
};
use crate::steps::sinks::{FetchSink, is_http_sink_call};
use crate::steps::sources::BodySource;
use crate::steps::{StepCtx, StepKind};
use crate::{ExtractOutput, Rule, RuleContext, RuleMeta};

const RULE_ID: &str = "flow/ssrf-via-fetch";

/// Step registry consulted by [`SsrfVisitor`]. Body taint flows
/// from [`BodySource`] into the URL argument of [`FetchSink`]-shaped
/// calls; slice 1 records no sanitiser steps yet (URL allow-list
/// recognition is slice 2).
const RULE_STEPS: &[StepKind] = &[
    StepKind::BodySource(BodySource),
    StepKind::FetchSink(FetchSink),
];

pub struct SsrfViaFetch;

impl SsrfViaFetch {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SsrfViaFetch {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SsrfViaFetch {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: RULE_ID,
            default_severity: Severity::High,
            description: "Untrusted request input reaches an outbound HTTP call as the URL without an allow-list check.",
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
        let mut visitor =
            SsrfVisitor::new_with_adapters(ctx.file.path.clone(), ctx.index, true, ctx.adapters);
        for stmt in &ctx.file.program.body {
            visitor.visit_statement(stmt);
        }
        visitor.findings
    }
}

struct SsrfVisitor<'idx> {
    file: PathBuf,
    /// Stack of per-function scopes; each scope maps binding name to
    /// `()` if that binding holds body-tainted data. Body-tainted
    /// shapes are over-approximated as whole-value taint for slice
    /// 1 — `const { url } = body` propagates taint to `url` even
    /// though only the `.url` member is structurally tainted.
    scopes: Vec<HashMap<String, ()>>,
    /// Slice 2 — URL-constructor lineage. Maps a binding name to
    /// the original ident passed into `new URL(...)`. Populated at
    /// var-decl sites of the shape `const parsed = new URL(input)`.
    /// Consumed by `visit_if_statement` when an allow-list guard
    /// (`if (!ALLOWED.has(parsed.host)) return ...`) proves the
    /// underlying input has been validated against an allow-list.
    /// Per-function — cleared in `enter_fn`.
    url_inits: HashMap<String, String>,
    /// Bindings whose initial value is operator-controlled — `process.env.X`,
    /// `process.env.X ?? "fallback"`, hardcoded string literals, or
    /// transitively another `safe_host_binding`. When such a binding
    /// is interpolated at the head of a template-literal URL
    /// (`fetch(\`${revalidateUrl}/api/...?id=${body.id}\`)`), the host
    /// portion of the URL is operator-pinned — body taint in the
    /// path/query becomes path-injection (Medium) rather than full
    /// SSRF (High). Without this map the recogniser only caught the
    /// `https://example.com/...` literal-prefix form, mis-classifying
    /// the env-var-prefix shape that's endemic in real Next.js codebases
    /// (papermark `revalidateLinkById` was the motivating OSS FP).
    ///
    /// Per-function — cleared in `enter_fn`. Reassignment is not
    /// tracked; `let`-mutable bindings holding env data and later
    /// overwritten with body data would fool the recogniser, but
    /// that shape is vanishingly rare in practice.
    safe_host_bindings: HashMap<String, ()>,
    /// Read-only project index. `Some` during the run pass (cross-file
    /// callee lookups go through it); `None` during the extract pass
    /// simulation (no findings are recorded then anyway, since extract
    /// only counts whether sinks fire, not where).
    index: Option<&'idx stryx_index::ProjectIndex>,
    /// Honour `body_source_active` at the step level — set to `true`
    /// for the run pass (body taint sources fire naturally) and
    /// `false` during per-param simulation (only the pre-tainted
    /// parameter contributes; ambient `req.body` reads must not turn
    /// into spurious sinks inside helpers that don't take a request).
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

impl<'idx> SsrfVisitor<'idx> {
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
            url_inits: HashMap::new(),
            safe_host_bindings: HashMap::new(),
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
        // URL-constructor lineage is per-function. A binding declared
        // inside one function should not leak its (parsed, input)
        // mapping into the next function the visitor walks.
        self.url_inits.clear();
        // Same scoping discipline for safe-host bindings.
        self.safe_host_bindings.clear();
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

    /// Returns `true` if `expr` carries body taint. Mirrors the
    /// structural-propagator walk used by `flow/unvalidated-body-to-db`
    /// but with slice 1's narrower coverage: no call-summary lookup,
    /// no validators, no chain-element subtleties beyond unwrap.
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

    /// Record taint on `pat` from a tainted RHS expression. Handles
    /// bare identifier (`const x = body`) and destructured-object
    /// shorthand (`const { url } = body` — `url` becomes tainted).
    /// Array patterns and rest elements are conservatively over-
    /// tainted: every named binding gets the taint.
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
        // Slice 2 — track `const parsed = new URL(INPUT)` lineage.
        // Recorded unconditionally; the consumer at the IfStatement
        // narrowing site only fires when the structural guard
        // matches. INPUT can be either a bare ident or a member
        // chain — we want to remember the bare-ident root so the
        // guard can untaint the right binding.
        if let Some(binding) = single_binding_name(&declarator.id)
            && let Some(input_name) = extract_url_constructor_input(init)
        {
            self.url_inits.insert(binding, input_name);
        }
        // Track operator-controlled bindings so host-pinned-template
        // recognition can see through one level of indirection
        // (`const revalidateUrl = process.env.NEXTAUTH_URL` →
        // `fetch(\`${revalidateUrl}/...\`)` is path-injection, not
        // full SSRF).
        if let Some(binding) = single_binding_name(&declarator.id)
            && self.is_safe_host_expr(init)
        {
            self.safe_host_bindings.insert(binding, ());
        }
        if self.expr_taint(init) {
            self.taint_pattern(&declarator.id);
        }
    }

    fn check_http_sink(&mut self, call: &CallExpression<'_>) {
        if !is_http_sink_call(call) || !self.registry_as_sink(call) {
            return;
        }
        let Some(first_arg) = call.arguments.first().and_then(argument_expr) else {
            return;
        };
        if !self.expr_taint(first_arg) {
            return;
        }
        // Severity tier — distinguish full-URL SSRF from
        // path-injection within a fixed host. When the first arg is
        // a template literal whose leading quasi pins the URL scheme
        // and host (`https://example.com/...`), the body data fills
        // only a path/query slot — bounded blast radius, downgrade
        // to Medium. Bare-ident shapes (`fetch(body.url)`) are
        // full SSRF, host-arbitrary → High.
        let (severity, message) = if self.is_host_pinned_template(first_arg) {
            (
                Severity::Medium,
                "Untrusted request input reaches an outbound HTTP call as a path/query segment within a fixed-host URL — path-injection surface against the pinned API.".to_string(),
            )
        } else {
            (
                Severity::High,
                "Untrusted request input reaches an outbound HTTP call as the URL without a recognised allow-list check.".to_string(),
            )
        };
        self.findings.push(
            Finding::ast(RULE_ID, severity, message, to_span(&self.file, call.span))
                .with_help(
                    "Parse the URL with `new URL(input)` and check the host against an allow-list before calling fetch/axios/got. For path-segment substitution, validate against an allow-list of expected path values and reject anything else with a 4xx response.",
                ),
        );
    }

    /// True iff `expr` is a template literal whose host portion is
    /// operator-pinned. Recognised shapes:
    ///
    /// 1. **Literal scheme prefix** — `https://example.com/...` or
    ///    `http://example.com/...`. The leading quasi carries the
    ///    scheme and a literal host before the first `/`.
    /// 2. **Env-prefix indirection** — `${revalidateUrl}/api/...` or
    ///    `${process.env.NEXTAUTH_URL}/api/...`. The leading quasi
    ///    is empty, the first interpolation is operator-controlled
    ///    (`process.env.X`, a fallback chain like `process.env.X ??
    ///    "..."`, or a binding previously initialised from one of
    ///    those), and the next quasi starts with `/` to delimit the
    ///    host portion.
    ///
    /// In a host-pinned template, body-tainted interpolations can
    /// only inject into the path/query — bounded blast radius
    /// against the pinned host. `check_http_sink` downgrades the
    /// severity from High (full SSRF) to Medium (path-injection).
    fn is_host_pinned_template(&self, expr: &Expression<'_>) -> bool {
        let mut cursor = expr;
        loop {
            match cursor {
                Expression::ParenthesizedExpression(p) => cursor = &p.expression,
                Expression::TSAsExpression(t) => cursor = &t.expression,
                Expression::TSNonNullExpression(t) => cursor = &t.expression,
                Expression::TSSatisfiesExpression(t) => cursor = &t.expression,
                Expression::TSTypeAssertion(t) => cursor = &t.expression,
                _ => break,
            }
        }
        let Expression::TemplateLiteral(t) = cursor else {
            return false;
        };
        let Some(leading) = t.quasis.first() else {
            return false;
        };
        let leading_raw = leading.value.cooked.as_deref().unwrap_or("");

        // Case 1 — literal scheme + host in the leading quasi.
        if leading_raw.starts_with("https://") || leading_raw.starts_with("http://") {
            let after_scheme = leading_raw
                .strip_prefix("https://")
                .or_else(|| leading_raw.strip_prefix("http://"))
                .unwrap_or("");
            return after_scheme
                .chars()
                .take_while(|c| *c != '/')
                .any(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
        }

        // Case 2 — empty leading quasi + safe-host first interpolation
        // + second quasi starting with `/` (path delimiter). The
        // host is determined entirely by an operator-controlled
        // expression; everything after `/` is path/query.
        if leading_raw.is_empty()
            && let Some(first_expr) = t.expressions.first()
            && self.is_safe_host_expr(first_expr)
            && let Some(second_quasi) = t.quasis.get(1)
        {
            let next_raw = second_quasi.value.cooked.as_deref().unwrap_or("");
            return next_raw.starts_with('/');
        }

        false
    }

    /// True iff `expr` is operator-controlled — `process.env.X`, a
    /// nullish/or fallback chain whose left side is safe
    /// (`process.env.X ?? "..."`), a parenthesised / TS-cast wrap of
    /// either, or a binding recorded in `safe_host_bindings`. Used
    /// both at var-decl sites (to populate the binding map) and at
    /// host-pinned-template recognition.
    fn is_safe_host_expr(&self, expr: &Expression<'_>) -> bool {
        let mut cursor = expr;
        loop {
            match cursor {
                Expression::ParenthesizedExpression(p) => cursor = &p.expression,
                Expression::TSAsExpression(t) => cursor = &t.expression,
                Expression::TSNonNullExpression(t) => cursor = &t.expression,
                Expression::TSSatisfiesExpression(t) => cursor = &t.expression,
                Expression::TSTypeAssertion(t) => cursor = &t.expression,
                // `process.env.X ?? "fallback"` / `process.env.X || "fallback"` —
                // both sides should be safe; the left determines the host.
                Expression::LogicalExpression(b)
                    if matches!(b.operator, LogicalOperator::Coalesce | LogicalOperator::Or) =>
                {
                    cursor = &b.left;
                }
                _ => break,
            }
        }
        match cursor {
            Expression::Identifier(id) => self.safe_host_bindings.contains_key(id.name.as_str()),
            // Bare `process.env.X` member chain.
            Expression::StaticMemberExpression(m) => {
                let Expression::StaticMemberExpression(inner) = &m.object else {
                    return false;
                };
                if inner.property.name != "env" {
                    return false;
                }
                matches!(
                    &inner.object,
                    Expression::Identifier(id) if id.name == "process"
                )
            }
            _ => false,
        }
    }

    /// Look up the callee through the project index — bare-ident
    /// imports and same-file top-level functions. Returns the
    /// ExportedFunctionSummary whose `params[i].reaches_fetch_sink_unsanitized`
    /// flag tells us whether passing tainted data at position `i`
    /// would reach an HTTP sink inside the callee.
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
    /// `reaches_fetch_sink_unsanitized` at that argument position,
    /// emit a finding. Severity follows the precision the extract
    /// pass recorded: High when any sink inside the callee was full
    /// SSRF, Medium when every sink the parameter reaches is a
    /// host-pinned template (path-injection only).
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
            if !summary.taints_through_fetch_param(i) {
                continue;
            }
            let param = summary.params.get(i);
            let param_name = param.map(|p| p.name.as_str()).unwrap_or("?");
            let path_pinned = param.is_some_and(|p| p.fetch_sink_path_pinned_only);
            let (severity, message) = if path_pinned {
                (
                    Severity::Medium,
                    format!(
                        "Untrusted request input flows into `{callee_label}` (param `{param_name}`), which makes an outbound HTTP call as a path/query segment within a fixed-host URL — path-injection surface against the pinned API."
                    ),
                )
            } else {
                (
                    Severity::High,
                    format!(
                        "Untrusted request input flows into `{callee_label}` (param `{param_name}`), which makes an outbound HTTP call without a recognised allow-list check."
                    ),
                )
            };
            self.findings.push(
                Finding::ast(RULE_ID, severity, message, to_span(&self.file, call.span))
                    .with_help(
                        "Validate the URL against an allow-list at this call site, or inside the called helper before the fetch/axios/got call.",
                    ),
            );
        }
    }
}

impl<'a, 'idx> Visit<'a> for SsrfVisitor<'idx> {
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
        self.check_http_sink(call);
        // Slice 2 — cross-file: when the run pass has an index, check
        // whether the callee's summary marks any tainted argument
        // position as reaching a fetch sink. During the extract pass
        // simulation `index` is None, so this is a no-op then.
        if self.index.is_some() {
            self.check_cross_file_call(call);
        }
        // Continue walking to find nested sinks (e.g. `fetch(maybe(body))`).
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
        // Slice 2 — URL allow-list guard narrowing. Pattern:
        //
        //   const parsed = new URL(input);
        //   if (!ALLOWED.has(parsed.host)) {
        //     return ...;
        //   }
        //   // past here, `input` is allow-listed
        //
        // Mirrors the discriminated-union validator pattern
        // (task #96) — track lineage at the var-decl site, consume
        // it at the narrowing site, untaint past the early return.
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
// Walk top-level decls. For each function-like export (FunctionDeclaration,
// `const x = (...)=>{}`, default-exported function/arrow), run a
// per-parameter simulation that pre-taints one param and observes whether
// the [`SsrfVisitor`] records a sink finding. Whatever the simulation
// observes lands on `ParamFlow::reaches_fetch_sink_unsanitized`.
//
// Slice 2 deliberately does *not* populate `param_shape`, `return_shape`,
// `tainted_offsets`, `propagates_to_return`, or class methods — those are
// the db rule's territory (and the merge_per_rule_flags contract keeps
// db's richer fields on collision). Slice 2's contribution is reach-only.

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
        // One param pre-tainted, body-source recognition disabled
        // (the simulation is interested only in whether *this* param
        // reaches a sink — not whether the helper happens to read
        // `req.body` directly, which is the route handler's job).
        // The visitor sees the *previous* round's index so cross-file
        // calls already known to sink contribute to the sink hit —
        // that's what makes summaries converge through multi-level
        // chains (route → service → client).
        let mut visitor = SsrfVisitor::new(file.to_path_buf(), index, false);
        visitor.taint(pname.clone());
        for stmt in body {
            visitor.visit_statement(stmt);
        }
        let reaches = !visitor.findings.is_empty();
        // Path-pinned-only iff at least one sink fired AND every fire
        // was the Medium (host-pinned) tier. Caller downgrades the
        // call-site finding from High to Medium when this is set.
        let path_pinned_only = reaches
            && visitor
                .findings
                .iter()
                .all(|f| f.severity == Severity::Medium);
        let sink_span = visitor.findings.first().map(|f| f.span.clone());
        params_out.push(ParamFlow {
            name: pname.clone(),
            reaches_fetch_sink_unsanitized: reaches,
            fetch_sink_path_pinned_only: path_pinned_only,
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
