//! `flow/auth-bypass-via-wrapper` — slice 1.
//!
//! Detects route handlers wrapped in a project-local `withAuth`-shaped
//! function whose implementation never calls a recognised authentication
//! helper. The wrapper *looks* protected from the call site; in reality
//! the body is a no-op or only adds incidental behaviour, leaving the
//! handler reachable without authentication.
//!
//! Cross-file by design: the wrapper definition lives in `lib/auth.ts`
//! while the route handler lives in `app/api/.../route.ts`. The rule
//! re-uses the project index built by `flow/unvalidated-body-to-db` —
//! every top-level/exported function already has an
//! `ExportedFunctionSummary` whose `contains_auth_check` flag we
//! populate via a shared helper at extract time.

use regex::Regex;
use stryx_ast::{
    ParsedFile, Visit,
    ast::{
        BindingPattern, CallExpression, Declaration, ExportDefaultDeclarationKind,
        ExportNamedDeclaration, Expression, Statement, VariableDeclarator,
    },
    to_span,
};
use stryx_core::{Finding, Severity};

use crate::adapters::{EnabledAdapters, GuardKind, MatcherContext, SanitizerKind};
use crate::steps::sanitizers::AuthCheckSanitizer;
use crate::steps::{StepCtx, StepKind};
use crate::{Rule, RuleContext, RuleMeta};

// `AUTH_HELPER_NAMES` and `call_invokes_auth_helper` moved to
// `crate::steps::sanitizers::auth` (ADR 0008 slice 8.3b). Re-export
// `AUTH_HELPER_NAMES` from this module so external consumers that
// import it via this rule's path keep working.
pub use crate::steps::sanitizers::AUTH_HELPER_NAMES;

const RULE_ID: &str = "flow/auth-bypass-via-wrapper";

/// Per-rule step registry. `AuthCheckSanitizer` recognises auth-helper
/// call sites; the body-walker in
/// [`contains_auth_helper_call`] dispatches through this registry
/// (slice 8.3b consumer).
const RULE_STEPS: &[StepKind] = &[StepKind::AuthCheckSanitizer(AuthCheckSanitizer)];

pub struct AuthBypassViaWrapper {
    wrapper_name_re: Regex,
}

impl AuthBypassViaWrapper {
    pub fn new() -> Self {
        // Names that *imply* authentication enforcement at a call site.
        // Deliberately narrow: we only flag wrappers whose name promises
        // auth and whose body delivers nothing.
        //
        // Examples that match: withAuth, withSession, withLogin, withUser,
        // withAuthentication, requireAuth, requireSession, requireUser,
        // needAuth, enforceAuth, protected, authed, secure, protect.
        let wrapper_name_re = Regex::new(
            r"^(?:with(?:Auth|Session|Login|User|Authentication)|(?:require|need|enforce)(?:Auth|Session|Login|User)|protected|authed|secure|protect)$",
        )
        .expect("static regex compiles");

        Self { wrapper_name_re }
    }

    fn looks_like_wrapper(&self, name: &str) -> bool {
        self.wrapper_name_re.is_match(name)
    }
}

impl Default for AuthBypassViaWrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for AuthBypassViaWrapper {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: RULE_ID,
            default_severity: Severity::Critical,
            description: "Route handler wrapped in an auth-named function whose body never verifies authentication.",
        }
    }

    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding> {
        let mut findings = Vec::new();
        let Some(index) = ctx.index else {
            return findings;
        };
        let file_path = ctx.file.path.clone();
        // `ctx.adapters` is threaded through the run pipeline to keep
        // this rule consistent with the substrate plumbing applied to
        // the body-source rules (`flow/sql-injection`, etc.). At this
        // slice the run pass reads the cached `contains_auth_check`
        // flag on each summary rather than re-walking wrapper bodies,
        // so the threaded `adapters` value is not yet consulted here;
        // a future slice that migrates the extract pass in
        // `flow/unvalidated-body-to-db` to populate the flag under
        // adapter context will use the same propagation path.
        for stmt in &ctx.file.program.body {
            match stmt {
                Statement::ExportNamedDeclaration(decl) => {
                    self.check_named_export(decl, &file_path, index, ctx.adapters, &mut findings);
                }
                Statement::ExportDefaultDeclaration(decl) => {
                    self.check_default_export(
                        &decl.declaration,
                        decl.span,
                        &file_path,
                        index,
                        ctx.adapters,
                        &mut findings,
                    );
                }
                _ => {}
            }
        }
        findings
    }
}

impl AuthBypassViaWrapper {
    fn check_named_export(
        &self,
        decl: &ExportNamedDeclaration<'_>,
        file: &std::path::Path,
        index: &stryx_index::ProjectIndex,
        adapters: Option<&EnabledAdapters>,
        out: &mut Vec<Finding>,
    ) {
        let Some(declaration) = &decl.declaration else {
            return;
        };
        let Declaration::VariableDeclaration(var) = declaration else {
            return;
        };
        for declarator in &var.declarations {
            self.check_declarator(declarator, file, index, adapters, out);
        }
    }

    fn check_default_export(
        &self,
        decl: &ExportDefaultDeclarationKind<'_>,
        decl_span: stryx_ast::OxcSpan,
        file: &std::path::Path,
        index: &stryx_index::ProjectIndex,
        adapters: Option<&EnabledAdapters>,
        out: &mut Vec<Finding>,
    ) {
        // `export default withAuth(handler)` — the declaration is a
        // CallExpression in oxc's `ExportDefaultDeclarationKind` enum.
        if let ExportDefaultDeclarationKind::CallExpression(call) = decl {
            self.check_wrapper_call(call, file, index, adapters, out, decl_span);
        }
    }

    fn check_declarator(
        &self,
        declarator: &VariableDeclarator<'_>,
        file: &std::path::Path,
        index: &stryx_index::ProjectIndex,
        adapters: Option<&EnabledAdapters>,
        out: &mut Vec<Finding>,
    ) {
        let Some(init) = &declarator.init else {
            return;
        };
        // Only flag handlers — exported HTTP method names. Other
        // wrapped exports may legitimately be helpers or middleware
        // chains where "withAuth" composes with something else.
        let Some(name) = single_binding_name(&declarator.id) else {
            return;
        };
        if !is_route_handler_name(&name) {
            return;
        }
        let Expression::CallExpression(call) = init else {
            return;
        };
        self.check_wrapper_call(call, file, index, adapters, out, declarator.span);
    }

    /// At a route-handler export site, check whether the call's callee
    /// is wrapper-shaped (by name) and resolves to a function body that
    /// never calls a recognised auth helper.
    fn check_wrapper_call(
        &self,
        call: &CallExpression<'_>,
        file: &std::path::Path,
        index: &stryx_index::ProjectIndex,
        _adapters: Option<&EnabledAdapters>,
        out: &mut Vec<Finding>,
        site_span: stryx_ast::OxcSpan,
    ) {
        let Expression::Identifier(callee) = &call.callee else {
            return;
        };
        let wrapper_name = callee.name.as_str();
        if !self.looks_like_wrapper(wrapper_name) {
            return;
        }
        // Resolve the wrapper's summary. Cross-file via imports first,
        // then same-file exports/locals.
        let summary = index.resolve_summary(file, wrapper_name).or_else(|| {
            let f = index.file(file)?;
            f.exports
                .get(wrapper_name)
                .or_else(|| f.locals.get(wrapper_name))
        });
        let Some(summary) = summary else {
            // Wrapper is imported from `node_modules` or another
            // unresolved source. v0.0.1 doesn't escalate; we silently
            // pass. (Slice 2 will emit an UncertainZone here.)
            return;
        };
        if summary.contains_auth_check {
            return;
        }
        out.push(
            Finding::ast(
                RULE_ID,
                Severity::Critical,
                format!(
                    "Route handler is wrapped in `{wrapper_name}`, but its definition never calls a recognised authentication helper.",
                ),
                to_span(file, site_span),
            )
            .with_help(
                "Either implement the wrapper to verify the session and short-circuit on failure (e.g. `getServerSession`, `auth()`, `lucia.validateRequest`), or rename it so its name doesn't imply authentication.",
            ),
        );
    }
}

// ── Shared helper: contains_auth_helper_call ─────────────────────────────

/// Walks `body` recursively (including nested function expressions) and
/// returns true if any call site invokes a recognised authentication
/// helper. Recognition is the OR of the hardcoded
/// [`AUTH_HELPER_NAMES`] list (via [`AuthCheckSanitizer`]) and — when
/// an active adapter set is wired in — any pattern contributed by an
/// adapter as [`SanitizerKind::AuthCheck`] or
/// [`GuardKind::SessionRequired`].
///
/// This entry point keeps its original signature so existing callers
/// in the extract pass of `flow/unvalidated-body-to-db` continue to
/// behave byte-identically (no file path / index / adapters available
/// during raw-body extraction). Callers that have a `ParsedFile` and
/// (optionally) adapters in hand should prefer
/// [`contains_auth_helper_call_with_adapters`] so adapter-contributed
/// auth-helper shapes (`@clerk/nextjs/server` `auth()`,
/// `better-auth` `getSession()`, `next-auth` `auth()`, etc.) are
/// recognised in addition to the hardcoded names.
///
/// Used by:
/// - This rule's run pass (indirectly, via the cached
///   `contains_auth_check` flag on each `ExportedFunctionSummary`).
/// - `flow/unvalidated-body-to-db`'s `build_summary` populates that
///   flag by calling this helper once per function.
pub fn contains_auth_helper_call(body: &[Statement<'_>]) -> bool {
    contains_auth_helper_call_with_adapters(body, None, None, None)
}

/// Adapter-aware variant of [`contains_auth_helper_call`]. When
/// `adapters` is `Some`, an additional OR-fallback consults every
/// [`SanitizerKind::AuthCheck`] sanitiser pattern and every
/// [`GuardKind::SessionRequired`] guard pattern an active adapter
/// contributes, matching each pattern's [`AstMatcher`]s against the
/// current call expression. Recognition is strictly additive: a call
/// the hardcoded list already recognises continues to fire; adapters
/// can only add more recognitions, never remove them.
///
/// `file` and `index` are forwarded to the matcher dispatch so
/// shapes that need import context (e.g.
/// [`AstMatcher::ImportedCall`] resolving `@clerk/nextjs/server`'s
/// `auth`) can resolve. Passing `None` for both is equivalent to the
/// non-adapter path — import-resolving matchers will simply not fire.
///
/// [`AstMatcher`]: crate::adapters::AstMatcher
/// [`AstMatcher::ImportedCall`]: crate::adapters::AstMatcher::ImportedCall
pub fn contains_auth_helper_call_with_adapters<'a>(
    body: &[Statement<'a>],
    file: Option<&'a ParsedFile<'_>>,
    index: Option<&stryx_index::ProjectIndex>,
    adapters: Option<&EnabledAdapters>,
) -> bool {
    let mut visitor = AuthCheckVisitor {
        found: false,
        file,
        index,
        adapters,
    };
    for stmt in body {
        visitor.visit_statement(stmt);
        if visitor.found {
            return true;
        }
    }
    false
}

struct AuthCheckVisitor<'a, 'idx> {
    found: bool,
    /// Optional parsed file used to construct a [`MatcherContext`] for
    /// the adapter-driven OR-fallback. `None` on the hardcoded path
    /// (raw-body extraction); `Some` when an adapter-aware caller
    /// passes one in.
    file: Option<&'a ParsedFile<'idx>>,
    /// Optional project index — forwarded to the matcher dispatch so
    /// `ImportedCall` shapes can resolve. `None` mirrors the
    /// hardcoded path's lack of import context.
    index: Option<&'a stryx_index::ProjectIndex>,
    /// Active stack adapters. `None` reproduces the pre-substrate
    /// behaviour (hardcoded `AUTH_HELPER_NAMES` only). `Some` enables
    /// the OR-fallback against `SanitizerKind::AuthCheck` and
    /// `GuardKind::SessionRequired` patterns.
    adapters: Option<&'a EnabledAdapters>,
}

impl<'a, 'idx> AuthCheckVisitor<'a, 'idx> {
    /// Adapter-driven OR-fallback. Returns true iff `expr` matches
    /// any [`AstMatcher`] on any `AuthCheck` sanitiser pattern or
    /// `SessionRequired` guard pattern contributed by an active
    /// adapter. Pure read.
    ///
    /// The auth adapters (`auth/better-auth`, `auth/auth-js`,
    /// `auth/clerk`) intentionally co-register the same matchers
    /// under both `SanitizerKind::AuthCheck` and
    /// `GuardKind::SessionRequired`. OR-including both roles gives
    /// us the full recognition surface for "this call counts as a
    /// real session check" — if an adapter ever contributes a guard
    /// shape that isn't also a sanitiser (or vice versa), both arms
    /// pick it up without coordination.
    ///
    /// [`AstMatcher`]: crate::adapters::AstMatcher
    fn matches_adapter_auth_pattern(&self, expr: &Expression<'_>) -> bool {
        let Some(adapters) = self.adapters else {
            return false;
        };
        let Some(file) = self.file else {
            return false;
        };
        let mctx = MatcherContext {
            file,
            index: self.index,
        };
        for pat in adapters
            .sanitisers
            .iter()
            .filter(|p| p.sanitizer == SanitizerKind::AuthCheck)
        {
            if pat.matchers.iter().any(|m| m.matches(&mctx, expr)) {
                return true;
            }
        }
        for pat in adapters
            .guards
            .iter()
            .filter(|p| p.guard == GuardKind::SessionRequired)
        {
            if pat.matchers.iter().any(|m| m.matches(&mctx, expr)) {
                return true;
            }
        }
        false
    }
}

impl<'a, 'idx> Visit<'a> for AuthCheckVisitor<'a, 'idx> {
    fn visit_expression(&mut self, expr: &Expression<'a>) {
        if self.found {
            return;
        }
        // Adapter-driven OR-fallback runs on the `&Expression` surface
        // so the substrate's `AstMatcher::matches` can dispatch on
        // every call shape it recognises (`ImportedCall`,
        // `NamespaceCall`, `MethodCall`, `MethodCallAnyReceiver`).
        // Strictly additive: short-circuits to `false` when
        // `adapters` / `file` are `None` (the historical extract-pass
        // path that every existing fixture exercises), preserving
        // byte-identical behaviour.
        if self.matches_adapter_auth_pattern(expr) {
            self.found = true;
            return;
        }
        // Default descent — keeps the existing recursion semantics
        // (nested calls / arrow returns / argument expressions are
        // visited), which the hardcoded `visit_call_expression` hook
        // below consumes.
        stryx_ast::walk::walk_expression(self, expr);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.found {
            return;
        }
        // ADR 0008 — registry-dispatched auth-check recognition.
        // The body-walker stays where it lives; the per-call
        // predicate moved to `AuthCheckSanitizer`. The step's
        // `StepCtx` fields aren't consulted (auth recognition is
        // purely syntactic on the callee shape), so a sentinel ctx is
        // safe.
        let ctx = StepCtx {
            file: std::path::Path::new(""),
            index: None,
            body_source_active: false,
        };
        if RULE_STEPS.iter().any(|s| s.as_sanitizer(&ctx, call)) {
            self.found = true;
            return;
        }
        // Walk into nested calls / arrow returns / argument expressions.
        stryx_ast::walk::walk_call_expression(self, call);
    }
}

// ── Tiny utilities ────────────────────────────────────────────────────────

fn single_binding_name(pat: &BindingPattern<'_>) -> Option<String> {
    if let BindingPattern::BindingIdentifier(id) = pat {
        Some(id.name.to_string())
    } else {
        None
    }
}

/// Names of HTTP method exports that the engine recognises as route
/// handlers. Matches the App Router and Pages Router conventions.
fn is_route_handler_name(name: &str) -> bool {
    matches!(
        name,
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD" | "handler" | "default"
    )
}
