//! Eval-style sink step — JavaScript runtime-code-execution APIs for
//! the `flow/eval-injection` rule.
//!
//! Recognised shapes:
//!
//! - `eval(<code>)` — bare identifier callee. The classic dynamic-code
//!   entry point; the string is parsed and executed under the caller's
//!   identity.
//! - `Function(<code>)` and `new Function(<code>)` — the Function
//!   constructor. The last argument is a string of function body code
//!   that is parsed and bound as a callable; treating it as a sink is
//!   appropriate because any caller will invoke the result. We flag
//!   on the FIRST argument the same way `eval` is flagged — slice 1
//!   doesn't try to be clever about multi-argument constructor forms.
//! - `setTimeout(<code>, ...)` and `setInterval(<code>, ...)` — when
//!   the first argument is a STRING payload (not a function), the
//!   runtime calls it through eval semantics ("implied eval"). When
//!   the first argument is a function or arrow expression the call is
//!   benign and this sink does NOT match — the recogniser exposes a
//!   companion helper [`first_arg_is_function_like`] that the
//!   consuming rule uses to suppress the false positive.
//!
//! Severity hint is `Critical` — eval-style RCE under the app's
//! process identity, OWASP A03 and CWE-95.

use stryx_ast::ast::{Argument, CallExpression, Expression, NewExpression};

fn first_arg_expression<'a, 'b>(call: &'a CallExpression<'b>) -> Option<&'a Expression<'b>> {
    let first = call.arguments.first()?;
    match first {
        Argument::SpreadElement(_) => None,
        _ => first.as_expression(),
    }
}
use stryx_core::Severity;

use crate::steps::{SinkSpec, StepCtx, TaintStep};

/// Names handled as eval-style callees.
const EVAL_NAMES: &[&str] = &["eval", "Function"];

/// Names of timer APIs that interpret a string first argument as
/// code (the "implied eval" shape).
const TIMER_NAMES: &[&str] = &["setTimeout", "setInterval"];

/// Eval-style sink recogniser. Stateless; the [`StepCtx`] is unused.
#[derive(Debug, Default, Clone, Copy)]
pub struct EvalSink;

impl TaintStep for EvalSink {
    fn as_sink(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> Option<SinkSpec> {
        if is_eval_sink_call(call) {
            Some(SinkSpec {
                severity_hint: Severity::Critical,
            })
        } else {
            None
        }
    }
}

/// True iff `call` is a recognised eval-style call expression:
/// - `eval(...)` / `Function(...)`
/// - `setTimeout(<non-function>, ...)` / `setInterval(<non-function>, ...)`
///
/// Timer calls where the first argument is a function expression or
/// arrow function are not eval shapes and return `false`.
pub fn is_eval_sink_call(call: &CallExpression<'_>) -> bool {
    let Expression::Identifier(id) = &call.callee else {
        return false;
    };
    let name = id.name.as_str();
    if EVAL_NAMES.contains(&name) {
        return true;
    }
    if TIMER_NAMES.contains(&name) {
        // `setTimeout(fn, delay)` is benign; only the string-payload
        // shape executes through eval semantics.
        return !first_arg_is_function_like(call);
    }
    false
}

/// True iff `new <Callee>(...)` is `new Function(...)` — the
/// constructor form of the dynamic-code sink.
pub fn is_eval_new_expression(new_expr: &NewExpression<'_>) -> bool {
    matches!(
        &new_expr.callee,
        Expression::Identifier(id) if id.name.as_str() == "Function"
    )
}

/// True iff the call's first argument is an inline function or arrow
/// expression. Used by the recogniser to skip the benign
/// `setTimeout(() => ..., 1000)` shape and by callers that need the
/// same distinction at a finding site.
pub fn first_arg_is_function_like(call: &CallExpression<'_>) -> bool {
    matches!(
        first_arg_expression(call),
        Some(Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_))
    )
}
