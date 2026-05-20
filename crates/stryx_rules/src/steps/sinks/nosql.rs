//! NoSQL-call sink step — MongoDB collection-method recogniser for
//! the `flow/nosql-injection` rule.
//!
//! Recognised shapes:
//!
//! - `<x>.find(<query>, ...)` / `<x>.findOne(<query>, ...)` —
//!   read paths on the official `mongodb` driver, Mongoose model
//!   instances, and conventional `db.collection('users')`
//!   handles.
//! - `<x>.updateOne(...)` / `<x>.updateMany(...)` /
//!   `<x>.replaceOne(...)` — write paths whose first argument is
//!   the *filter* document; operator injection on the filter lets
//!   the attacker target any row.
//! - `<x>.deleteOne(...)` / `<x>.deleteMany(...)` — delete by
//!   filter; same operator-injection class.
//! - `<x>.aggregate(...)` / `<x>.countDocuments(...)` — read
//!   paths whose first argument is a query / pipeline whose stages
//!   can carry operator injection.
//! - Legacy collection methods `update` / `remove` / `count`,
//!   retained for older codebases still on the pre-4.x mongodb
//!   driver.
//!
//! Severity hint is `High` — MongoDB operator injection
//! (`{$gt: ""}`, `{$ne: null}`, `{$where: "..."}`, etc.) defeats
//! authentication, leaks rows, and on `$where` can execute
//! attacker-supplied JavaScript inside the database engine
//! (CWE-943 / NVD reports across Express+Mongo tutorials).
//!
//! Critical FP-avoidance: this recogniser requires the call's
//! first argument to be an **object literal** (`{...}`). That
//! eliminates the entire `Array.prototype.find(callback)` false
//! positive class — `Array.find` takes a function, not an object
//! expression. Lodash's `_.find(arr, {k: v})` shape could still
//! match; the rule doc documents this as a known FP zone.

use stryx_ast::ast::{CallExpression, Expression, MemberExpression};
use stryx_core::Severity;

use crate::steps::{SinkSpec, StepCtx, TaintStep};

/// MongoDB collection-method sink recogniser. Stateless; the
/// [`StepCtx`] is unused.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSqlSink;

impl TaintStep for NoSqlSink {
    fn as_sink(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> Option<SinkSpec> {
        if is_nosql_query_sink_call(call) {
            Some(SinkSpec {
                severity_hint: Severity::High,
            })
        } else {
            None
        }
    }
}

/// True iff `call` is one of the recognised MongoDB collection-method
/// shapes *and* its first argument is an object literal.
///
/// The object-literal requirement is the load-bearing FP guard: it
/// eliminates `Array.prototype.find(callback)` and similar
/// non-database `.find(fn)` shapes that share the method name.
pub fn is_nosql_query_sink_call(call: &CallExpression<'_>) -> bool {
    if !is_mongo_method_shape(call) {
        return false;
    }
    matches!(
        call.arguments.first().and_then(|a| a.as_expression()),
        Some(Expression::ObjectExpression(_))
    )
}

/// Method-name + receiver-shape check, ignoring arguments. Split out
/// so the visitor can re-use it if it ever needs to inspect a
/// matched call before the object-expression gate (slice 1 does
/// not).
fn is_mongo_method_shape(call: &CallExpression<'_>) -> bool {
    let Some(MemberExpression::StaticMemberExpression(method)) = call.callee.as_member_expression()
    else {
        return false;
    };
    if !is_mongo_collection_method(method.property.name.as_str()) {
        return false;
    }
    receiver_looks_like_mongo(&method.object)
}

/// MongoDB collection methods whose first argument is a *query
/// filter document* (or pipeline starting with `$match`). Keep this
/// list tight — methods like `insertOne` / `insertMany` take a
/// *document to insert* rather than a filter, so operator injection
/// on the first arg does not apply.
fn is_mongo_collection_method(name: &str) -> bool {
    matches!(
        name,
        "find"
            | "findOne"
            | "updateOne"
            | "updateMany"
            | "deleteOne"
            | "deleteMany"
            | "replaceOne"
            | "aggregate"
            | "countDocuments"
            // legacy pre-4.x mongodb driver / Mongoose holdovers
            | "update"
            | "remove"
            | "count"
    )
}

/// Receiver-shape predicate. Conservative for slice 1 — we accept
/// any of:
///
/// - A bare identifier (`db.find(...)`, `users.find(...)`,
///   `User.find(...)`). The object-literal gate above keeps the
///   FP rate manageable.
/// - A static-member chain (`db.collection.find(...)`,
///   `mongoose.models.User.find(...)`).
/// - A call expression (`db.collection('users').find(...)`,
///   `mongoose.model('User').find(...)`) — the canonical mongodb
///   driver and Mongoose shapes.
fn receiver_looks_like_mongo(object: &Expression<'_>) -> bool {
    matches!(
        object,
        Expression::Identifier(_)
            | Expression::StaticMemberExpression(_)
            | Expression::CallExpression(_)
    )
}
