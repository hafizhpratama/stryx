//! Parser-style sanitiser step ([ADR 0008] slice 8.3a).
//!
//! Recognises validator calls that consume an untrusted value and
//! return a schema-conformant result. Three syntactic shapes:
//!
//! - `<schema>.parse(input)` / `.safeParse(input)` / `.parseAsync` /
//!   `.safeParseAsync` — zod, valibot, yup, arktype, runtypes.
//! - `parse(input, { schema })` — `@conform-to/zod`'s free-function
//!   form (and the parallel `@conform-to/yup`, `@conform-to/valibot`).
//!   The schema-key requirement keeps recognition conservative — a
//!   generic `parse(text, base)` integer parser doesn't match.
//! - `stripe.webhooks.constructEvent(body, sig, secret)` — Stripe
//!   webhook signature verification, which throws on a bad signature
//!   and returns the typed event on success.
//!
//! Free-standing predicates [`is_sanitizer_call`] and
//! [`second_arg_has_schema_key`] are `pub` so legacy call sites in
//! [`crate::flows::unvalidated_body_to_db`] can keep importing them
//! through the migration. The trait method
//! [`TaintStep::as_sanitizer`] dispatches via [`StepKind`]'s
//! closed-enum match.
//!
//! [ADR 0008]: ../../../../../docs/decisions/0008-taint-step-trait-substrate.md
//! [`StepKind`]: crate::steps::StepKind

use stryx_ast::ast::{
    Argument, CallExpression, Expression, MemberExpression, ObjectPropertyKind, PropertyKey,
};

use crate::steps::{StepCtx, TaintStep};

/// Parser-style sanitiser recogniser. Stateless; the [`StepCtx`] is
/// unused — recognition is purely syntactic.
#[derive(Debug, Default, Clone, Copy)]
pub struct ParserSanitizer;

impl TaintStep for ParserSanitizer {
    fn as_sanitizer(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> bool {
        is_sanitizer_call(call)
    }
}

pub fn is_sanitizer_call(call: &CallExpression<'_>) -> bool {
    // Free-function form: `parse(input, { schema })`. Stryx requires
    // the second argument to be an object literal containing a
    // `schema` property — distinguishes the conform shape from
    // generic `parse(x, y)` calls.
    if let Expression::Identifier(id) = &call.callee
        && id.name == "parse"
        && second_arg_has_schema_key(call)
    {
        return true;
    }

    let Some(callee) = call.callee.as_member_expression() else {
        return false;
    };
    let MemberExpression::StaticMemberExpression(method) = callee else {
        return false;
    };
    let prop = method.property.name.as_str();

    // Zod / valibot / yup / arktype / runtypes parser style: any
    // object exposing `.parse`, `.safeParse`, `.parseAsync`, or
    // `.safeParseAsync`. Covers `Schema.parse(body)`,
    // `CreateUserSchema.safeParse(...)`, etc.
    if matches!(
        prop,
        "parse" | "safeParse" | "parseAsync" | "safeParseAsync"
    ) {
        return true;
    }

    // Stripe webhook signature verification:
    //   `stripe.webhooks.constructEvent(body, signature, secret)`
    // Throws on bad signature; on success returns a verified
    // `Stripe.Event` whose shape is enforced by the Stripe SDK.
    // Treat it as a sanitiser.
    if prop == "constructEvent"
        && let Expression::StaticMemberExpression(inner) = &method.object
        && inner.property.name == "webhooks"
    {
        return true;
    }

    false
}

/// True iff `call`'s second argument is an object-literal expression
/// containing a `schema` property (either shorthand `{ schema }` or
/// keyed `{ schema: <expr> }`). Used to distinguish conform-style
/// `parse(input, { schema })` from generic 2-arg `parse` calls.
pub fn second_arg_has_schema_key(call: &CallExpression<'_>) -> bool {
    let Some(second_arg) = call.arguments.get(1).and_then(argument_expr) else {
        return false;
    };
    let mut cursor = second_arg;
    loop {
        match cursor {
            Expression::ObjectExpression(obj) => {
                return obj.properties.iter().any(|p| match p {
                    ObjectPropertyKind::ObjectProperty(prop) => {
                        matches!(
                            &prop.key,
                            PropertyKey::StaticIdentifier(id) if id.name == "schema"
                        )
                    }
                    ObjectPropertyKind::SpreadProperty(_) => false,
                });
            }
            // Trivial wrappers — drill through.
            Expression::ParenthesizedExpression(p) => cursor = &p.expression,
            Expression::TSAsExpression(t) => cursor = &t.expression,
            Expression::TSSatisfiesExpression(t) => cursor = &t.expression,
            _ => return false,
        }
    }
}

/// Local copy of the visitor's argument-expression accessor. Stays
/// here so the predicate module doesn't depend on rule internals.
fn argument_expr<'a, 'b>(arg: &'a Argument<'b>) -> Option<&'a Expression<'b>> {
    match arg {
        Argument::SpreadElement(_) => None,
        _ => arg.as_expression(),
    }
}
