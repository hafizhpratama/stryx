//! Unsafe-deserialization sink step — recogniser for the
//! [`crate::flows::insecure_deserialize`] rule.
//!
//! Recognised shapes (all of these execute arbitrary code when
//! handed attacker-controlled input):
//!
//! - `<x>.unserialize(...)` — `node-serialize`'s `unserialize`
//!   evaluates `IIFE`-wrapped function payloads on parse. The
//!   receiver name is unconstrained because the package is
//!   typically aliased as `serialize` (its default export name)
//!   but can be renamed by the importer. The bare-ident shape
//!   `unserialize(...)` after a destructured import is also
//!   recognised.
//! - `<x>.load(...)` where `<x>` is `yaml` / `jsyaml` / `YAML` —
//!   `js-yaml`'s `yaml.load` resolves arbitrary YAML tags
//!   including the `!!js/function` tag that materialises a JS
//!   function from a string. Discriminates on the *property* name
//!   `load`; **`safeLoad` is explicitly excluded** because it
//!   only resolves the safe schema subset and is the documented
//!   safe variant.
//! - `<x>.runInNewContext(...)` / `<x>.runInThisContext(...)` /
//!   `<x>.runInContext(...)` where `<x>` is `vm` — Node's `vm`
//!   module evaluates its first argument as a JavaScript program.
//!   Any attacker-controlled value at the first arg position is
//!   arbitrary code execution.
//!
//! Severity hint is `Critical` — all matched shapes are direct
//! RCE (OWASP A08:2021 — Software and Data Integrity Failures /
//! CWE-502 — Deserialization of Untrusted Data).
//!
//! Explicitly **not** matched (would produce false positives or
//! is out-of-scope for v1):
//!
//! - `JSON.parse(...)` — never executes code; treating it as a
//!   sink would fire on every Express body-parser usage in the
//!   ecosystem.
//! - `yaml.safeLoad(...)` — the documented safe variant of
//!   `js-yaml`.
//! - `vm.compileFunction(...)` — dangerous but rarely seen on
//!   request paths; deferred to a later slice.
//! - `libxmljs.parseXml(..., { noent: true })` — XXE; the
//!   options-arg shape adds complexity disproportionate to the
//!   v1 slice and is deferred.

use stryx_ast::ast::{CallExpression, Expression, MemberExpression};
use stryx_core::Severity;

use crate::steps::{SinkSpec, StepCtx, TaintStep};

/// Receivers we recognise for the `yaml.load(...)` shape. `js-yaml`
/// is the dominant npm YAML package; consumers conventionally alias
/// the namespace import as `yaml`, the camel-collapsed `jsyaml`, or
/// the upper-case `YAML` (the convention used by `eemeli/yaml`'s
/// types and a handful of tutorials).
const YAML_RECEIVERS: &[&str] = &["yaml", "jsyaml", "YAML"];

/// The three `vm` methods that evaluate a string of source code as
/// a JavaScript program. `compileFunction` is also dangerous but
/// deferred (see module-level docs).
const VM_RUN_METHODS: &[&str] = &["runInNewContext", "runInThisContext", "runInContext"];

/// Insecure-deserialization sink recogniser. Stateless; the
/// [`StepCtx`] is unused.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeserializeSink;

impl TaintStep for DeserializeSink {
    fn as_sink(&self, _ctx: &StepCtx<'_, '_>, call: &CallExpression<'_>) -> Option<SinkSpec> {
        if is_deserialize_sink_call(call) {
            Some(SinkSpec {
                severity_hint: Severity::Critical,
            })
        } else {
            None
        }
    }
}

/// True iff `call` is one of the recognised unsafe-deserialization
/// shapes. See the module-level docs for the full list and the
/// explicit-exclusion rationale.
pub fn is_deserialize_sink_call(call: &CallExpression<'_>) -> bool {
    match &call.callee {
        // Bare-ident `unserialize(...)` — produced by
        // `const { unserialize } = require("node-serialize")` or
        // `import { unserialize } from "node-serialize"`. Bare
        // `load(...)` is intentionally not matched: the bare name
        // is too generic and would fire on unrelated helpers.
        Expression::Identifier(id) => id.name == "unserialize",
        Expression::StaticMemberExpression(_) => {
            let Some(MemberExpression::StaticMemberExpression(method)) =
                call.callee.as_member_expression()
            else {
                return false;
            };
            let property = method.property.name.as_str();

            // `<x>.unserialize(...)` — receiver is unconstrained.
            // The method name is specific enough that this is a
            // safe gate; the canonical receiver is `serialize`
            // (node-serialize's default export name) but
            // re-aliasing is common.
            if property == "unserialize" {
                return true;
            }

            // `<x>.load(...)` for `<x>` in YAML_RECEIVERS only.
            // CRITICAL: `safeLoad` discriminates here and is NOT
            // matched. The property-name check above is `load`,
            // exact-string, so `safeLoad` falls through.
            if property == "load"
                && matches!(
                    &method.object,
                    Expression::Identifier(id) if YAML_RECEIVERS.contains(&id.name.as_str())
                )
            {
                return true;
            }

            // `vm.runInNewContext(...)` / `runInThisContext(...)` /
            // `runInContext(...)`. Receiver name `vm` only — the
            // method names are generic enough that we don't want to
            // match arbitrary objects with a `runInNewContext`
            // method.
            if VM_RUN_METHODS.contains(&property)
                && matches!(
                    &method.object,
                    Expression::Identifier(id) if id.name == "vm"
                )
            {
                return true;
            }

            false
        }
        _ => false,
    }
}
