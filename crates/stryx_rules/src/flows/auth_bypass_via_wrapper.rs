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
    Visit,
    ast::{
        BindingPattern, CallExpression, Declaration, ExportDefaultDeclarationKind,
        ExportNamedDeclaration, Expression, Statement, VariableDeclarator,
    },
    to_span,
};
use stryx_core::{Finding, Severity};

use crate::{Rule, RuleContext, RuleMeta};

const RULE_ID: &str = "flow/auth-bypass-via-wrapper";

/// Recognised auth-helper function names. A wrapper whose body invokes
/// any of these (anywhere — including nested arrow returns) is treated
/// as "actually verifies authentication".
///
/// Bare names match `getServerSession(opts)`; member-access matches
/// `auth.protect()`, `clerk.currentUser()`, `lucia.validateRequest()`.
pub const AUTH_HELPER_NAMES: &[&str] = &[
    "getServerSession",
    "getSession",
    "auth",
    "validateRequest",
    "getAuth",
    "currentUser",
    "getUser",
    "requireSession",
    "requireUser",
    "protect",
    "isAuthenticated",
    "verifyToken",
    "verifySession",
];

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
        for stmt in &ctx.file.program.body {
            match stmt {
                Statement::ExportNamedDeclaration(decl) => {
                    self.check_named_export(decl, &file_path, index, &mut findings);
                }
                Statement::ExportDefaultDeclaration(decl) => {
                    self.check_default_export(
                        &decl.declaration,
                        decl.span,
                        &file_path,
                        index,
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
        out: &mut Vec<Finding>,
    ) {
        let Some(declaration) = &decl.declaration else {
            return;
        };
        let Declaration::VariableDeclaration(var) = declaration else {
            return;
        };
        for declarator in &var.declarations {
            self.check_declarator(declarator, file, index, out);
        }
    }

    fn check_default_export(
        &self,
        decl: &ExportDefaultDeclarationKind<'_>,
        decl_span: stryx_ast::OxcSpan,
        file: &std::path::Path,
        index: &stryx_index::ProjectIndex,
        out: &mut Vec<Finding>,
    ) {
        // `export default withAuth(handler)` — the declaration is a
        // CallExpression in oxc's `ExportDefaultDeclarationKind` enum.
        if let ExportDefaultDeclarationKind::CallExpression(call) = decl {
            self.check_wrapper_call(call, file, index, out, decl_span);
        }
    }

    fn check_declarator(
        &self,
        declarator: &VariableDeclarator<'_>,
        file: &std::path::Path,
        index: &stryx_index::ProjectIndex,
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
        self.check_wrapper_call(call, file, index, out, declarator.span);
    }

    /// At a route-handler export site, check whether the call's callee
    /// is wrapper-shaped (by name) and resolves to a function body that
    /// never calls a recognised auth helper.
    fn check_wrapper_call(
        &self,
        call: &CallExpression<'_>,
        file: &std::path::Path,
        index: &stryx_index::ProjectIndex,
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
/// returns true if any call site invokes a name in `AUTH_HELPER_NAMES`.
///
/// Used by:
/// - This rule's run pass (indirectly, via the cached
///   `contains_auth_check` flag on each `ExportedFunctionSummary`).
/// - `flow/unvalidated-body-to-db`'s `build_summary` populates that
///   flag by calling this helper once per function.
pub fn contains_auth_helper_call(body: &[Statement<'_>]) -> bool {
    let mut visitor = AuthCheckVisitor { found: false };
    for stmt in body {
        visitor.visit_statement(stmt);
        if visitor.found {
            return true;
        }
    }
    false
}

struct AuthCheckVisitor {
    found: bool,
}

impl<'a> Visit<'a> for AuthCheckVisitor {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.found {
            return;
        }
        if call_invokes_auth_helper(call) {
            self.found = true;
            return;
        }
        // Walk into nested calls / arrow returns / argument expressions.
        stryx_ast::walk::walk_call_expression(self, call);
    }
}

fn call_invokes_auth_helper(call: &CallExpression<'_>) -> bool {
    let name = match &call.callee {
        Expression::Identifier(id) => id.name.as_str(),
        Expression::StaticMemberExpression(m) => m.property.name.as_str(),
        Expression::ChainExpression(c) => {
            // `auth?.()` / `auth?.protect()`
            return match &c.expression {
                stryx_ast::ast::ChainElement::CallExpression(inner) => {
                    call_invokes_auth_helper(inner)
                }
                _ => false,
            };
        }
        _ => return false,
    };
    AUTH_HELPER_NAMES.contains(&name)
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
