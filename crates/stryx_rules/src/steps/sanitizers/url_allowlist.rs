//! URL allow-list sanitiser helpers — shared between
//! [`crate::flows::ssrf_via_fetch`] and
//! [`crate::flows::redirect_open`].
//!
//! Both rules recognise the same canonical "URL allow-list" pattern:
//!
//! ```ignore
//! const parsed = new URL(input);
//! if (!ALLOWED.has(parsed.host)) {
//!   return ...;  // or throw
//! }
//! // input untainted past the guard
//! ```
//!
//! The pattern requires per-binding lineage tracking — `parsed`
//! must be tied back to `input` so the if-statement consumer
//! knows which binding to untaint. That state lives in each
//! rule's visitor as a `HashMap<String, String>`; this module
//! provides the *pure* helpers (constructor recognition, guard
//! pattern matching, branch-exit classification) that drive the
//! lineage tracking on both sides.
//!
//! Recognised allow-check shapes (negated, with early-return body):
//!
//! - `!ALLOWED.has(IDENT.host)` — `Set.has` / `Map.has`
//! - `!ALLOWED.includes(IDENT.hostname)` — `Array.includes`
//! - `!ALLOWED.includes(IDENT.origin)`
//! - `!validatorFn(IDENT.host)` where `validatorFn` is a bare
//!   identifier starting with `isAllowed` / `isValid` / `validate`
//!   / `verify` / `check` (slice 3).
//!
//! Positive-form guards (`if (ALLOWED.has(parsed.host)) { ... }`)
//! are not recognised — they'd require tracking the consequent's
//! narrowed branch instead of the post-If continuation. Deferred
//! until a motivating real-world FP shows up.

use stryx_ast::ast::{Argument, Expression, NewExpression, Statement, UnaryOperator};

/// Recognise `new URL(IDENT)` and return IDENT's name. Drills
/// through trivial wrappers (`await`, parens, TS casts) on both
/// the outer expression and the first argument so common shapes
/// like `new URL(input as string)` resolve correctly.
pub fn extract_url_constructor_input(expr: &Expression<'_>) -> Option<String> {
    let mut cursor = expr;
    loop {
        match cursor {
            Expression::AwaitExpression(a) => cursor = &a.argument,
            Expression::ParenthesizedExpression(p) => cursor = &p.expression,
            Expression::TSAsExpression(t) => cursor = &t.expression,
            Expression::TSNonNullExpression(t) => cursor = &t.expression,
            Expression::TSSatisfiesExpression(t) => cursor = &t.expression,
            Expression::TSTypeAssertion(t) => cursor = &t.expression,
            _ => break,
        }
    }
    let Expression::NewExpression(new_expr) = cursor else {
        return None;
    };
    if !is_url_callee(new_expr) {
        return None;
    }
    let first_arg = new_expr.arguments.first().and_then(argument_expr)?;
    extract_underlying_ident(first_arg)
}

fn is_url_callee(new_expr: &NewExpression<'_>) -> bool {
    matches!(&new_expr.callee, Expression::Identifier(id) if id.name == "URL")
}

/// Drill through trivial wrappers (parens, TS casts) and return
/// the underlying bare-identifier name.
fn extract_underlying_ident(expr: &Expression<'_>) -> Option<String> {
    let mut cursor = expr;
    loop {
        match cursor {
            Expression::Identifier(id) => return Some(id.name.to_string()),
            Expression::ParenthesizedExpression(p) => cursor = &p.expression,
            Expression::TSAsExpression(t) => cursor = &t.expression,
            Expression::TSNonNullExpression(t) => cursor = &t.expression,
            Expression::TSSatisfiesExpression(t) => cursor = &t.expression,
            Expression::TSTypeAssertion(t) => cursor = &t.expression,
            _ => return None,
        }
    }
}

/// Match the canonical URL allow-list guard. Returns the URL-binding
/// IDENT's name on match (so the caller can look it up in its
/// per-visitor lineage map).
pub fn match_url_allow_list_guard(test: &Expression<'_>) -> Option<String> {
    let Expression::UnaryExpression(unary) = test else {
        return None;
    };
    if unary.operator != UnaryOperator::LogicalNot {
        return None;
    }
    let mut cursor = &unary.argument;
    while let Expression::ParenthesizedExpression(p) = cursor {
        cursor = &p.expression;
    }
    let Expression::CallExpression(call) = cursor else {
        return None;
    };
    // Callee shape — either `X.has` / `X.includes`, or a bare
    // validator-named identifier.
    let callee_ok = match &call.callee {
        Expression::StaticMemberExpression(callee) => {
            matches!(callee.property.name.as_str(), "has" | "includes")
        }
        Expression::Identifier(id) => is_validator_callee_name(id.name.as_str()),
        _ => false,
    };
    if !callee_ok {
        return None;
    }
    // First argument must be `IDENT.host` / `IDENT.hostname` /
    // `IDENT.origin` — the URL-binding's member access.
    let arg = call.arguments.first().and_then(argument_expr)?;
    let mut cursor = arg;
    while let Expression::ParenthesizedExpression(p) = cursor {
        cursor = &p.expression;
    }
    let Expression::StaticMemberExpression(m) = cursor else {
        return None;
    };
    if !matches!(m.property.name.as_str(), "host" | "hostname" | "origin") {
        return None;
    }
    let Expression::Identifier(id) = &m.object else {
        return None;
    };
    Some(id.name.to_string())
}

/// True iff `name` looks like a host-validator function (leading
/// camelCase word from `isAllowed`/`isValid`/`validate`/`verify`/
/// `check`).
fn is_validator_callee_name(name: &str) -> bool {
    const PREFIXES: &[&str] = &["isAllowed", "isValid", "validate", "verify", "check"];
    PREFIXES.iter().any(|prefix| {
        if name.len() < prefix.len() {
            return false;
        }
        let (head, tail) = name.split_at(prefix.len());
        if !head.eq_ignore_ascii_case(prefix) {
            return false;
        }
        tail.is_empty() || tail.chars().next().is_some_and(|c| c.is_ascii_uppercase())
    })
}

/// True iff `branch` is guaranteed to leave the enclosing scope —
/// a bare return/throw statement, or a block whose body includes
/// one. Used to confirm the guard's consequent terminates so the
/// post-If continuation is the validated-input path.
pub fn branch_returns(branch: &Statement<'_>) -> bool {
    match branch {
        Statement::ReturnStatement(_) | Statement::ThrowStatement(_) => true,
        Statement::BlockStatement(bs) => bs
            .body
            .iter()
            .any(|s| matches!(s, Statement::ReturnStatement(_) | Statement::ThrowStatement(_))),
        _ => false,
    }
}

fn argument_expr<'a, 'b>(arg: &'a Argument<'b>) -> Option<&'a Expression<'b>> {
    match arg {
        Argument::SpreadElement(_) => None,
        _ => arg.as_expression(),
    }
}
