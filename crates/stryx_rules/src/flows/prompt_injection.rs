//! `flow/prompt-injection` — slice 1 (single-file).
//!
//! Detects request-body-tainted values reaching the prompt content
//! of an LLM provider call (`<x>.chat.completions.create`,
//! `<x>.responses.create`, `<x>.messages.create`). Slice 1 is
//! single-file and has no sanitiser recognition — schema
//! validation enforces *shape*, not prompt-injection safety, so
//! the canonical `zod.parse` shape is *not* a sanitiser here.
//!
//! The recogniser inspects the call's first-argument object
//! literal:
//!
//! - `messages: [{ role, content }, ...]` — every entry's `content`
//!   value is checked for body taint.
//! - `input: <expr>` — OpenAI Responses API; the bare expression
//!   is checked.
//!
//! See `docs/rules/flow-prompt-injection.md` for the rule's
//! contract and the bad/good fixtures it pins.
//!
//! Slice 2 (deferred) extends to cross-file via the same
//! `ExportedFunctionSummary` consumer used by
//! `flow/ssrf-via-fetch` and `flow/redirect-open`.

use std::collections::HashMap;

use stryx_ast::{
    Visit,
    ast::{
        Argument, ArrowFunctionExpression, AssignmentExpression, AssignmentTarget, BindingPattern,
        CallExpression, ChainElement, Expression, Function, ObjectExpression, ObjectPropertyKind,
        PropertyKey, VariableDeclarator,
    },
    to_span,
};
use stryx_core::{Finding, Severity};

use crate::steps::sinks::{LlmPromptSink, is_llm_prompt_sink_call};
use crate::steps::sources::BodySource;
use crate::steps::{StepCtx, StepKind};
use crate::{Rule, RuleContext, RuleMeta};

const RULE_ID: &str = "flow/prompt-injection";

const RULE_STEPS: &[StepKind] = &[
    StepKind::BodySource(BodySource),
    StepKind::LlmPromptSink(LlmPromptSink),
];

pub struct PromptInjection;

impl PromptInjection {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PromptInjection {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PromptInjection {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: RULE_ID,
            default_severity: Severity::High,
            description: "Untrusted request input reaches an LLM provider call as prompt or message content without instruction-vs-data separation.",
        }
    }

    fn run<'a, 'b>(&self, ctx: &RuleContext<'a, 'b>) -> Vec<Finding> {
        let mut visitor = PromptInjectionVisitor {
            file: ctx.file.path.clone(),
            scopes: vec![HashMap::new()],
            findings: Vec::new(),
        };
        for stmt in &ctx.file.program.body {
            visitor.visit_statement(stmt);
        }
        visitor.findings
    }
}

struct PromptInjectionVisitor {
    file: std::path::PathBuf,
    scopes: Vec<HashMap<String, ()>>,
    findings: Vec<Finding>,
}

impl PromptInjectionVisitor {
    fn step_ctx(&self) -> StepCtx<'_, 'static> {
        StepCtx {
            file: &self.file,
            index: None,
            body_source_active: true,
        }
    }

    fn enter_fn(&mut self) {
        self.scopes.push(HashMap::new());
    }

    fn exit_fn(&mut self) {
        self.scopes.pop();
    }

    fn taint(&mut self, name: String) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name, ());
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

    /// Standard body-taint walk — same shape as the other flow
    /// rules' single-file visitor.
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
        if self.expr_taint(init) {
            self.taint_pattern(&declarator.id);
        }
    }

    /// Inspect the call's first argument. If it's an object literal,
    /// check the `messages[].content` chain and the `input` slot for
    /// body taint. If the first arg is a non-literal (e.g. a tainted
    /// identifier holding the request object), conservatively flag
    /// the whole call.
    fn check_llm_sink(&mut self, call: &CallExpression<'_>) {
        if !is_llm_prompt_sink_call(call) || !self.registry_as_sink(call) {
            return;
        }
        let Some(first_arg) = call.arguments.first().and_then(argument_expr) else {
            return;
        };
        let tainted = match unwrap_trivia(first_arg) {
            Expression::ObjectExpression(obj) => self.prompt_fields_tainted(obj),
            other => self.expr_taint(other),
        };
        if !tainted {
            return;
        }
        self.findings.push(
            Finding::ast(
                RULE_ID,
                Severity::High,
                "Untrusted request input flows into an LLM provider call's prompt or message content without instruction-vs-data separation. Prompt injection: the user can override system instructions, exfiltrate prior context, or coerce the model into unintended actions.".to_string(),
                to_span(&self.file, call.span),
            )
            .with_help(
                "Wrap untrusted input in a structural delimiter (e.g. `<USER_INPUT>...</USER_INPUT>` tags), tell the model in the system prompt to treat the delimited region as data and never as instructions, and bound input length. Schema validation alone is *not* a prompt-injection defence.",
            ),
        );
    }

    /// True if any of the LLM call's prompt-bearing fields contains
    /// body-tainted data. Covers `messages: [{ role, content }, ...]`
    /// and OpenAI Responses API's `input: <expr>`.
    fn prompt_fields_tainted(&self, obj: &ObjectExpression<'_>) -> bool {
        for prop in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(p) = prop else {
                continue;
            };
            let PropertyKey::StaticIdentifier(key) = &p.key else {
                continue;
            };
            match key.name.as_str() {
                "messages" => {
                    if self.messages_array_tainted(&p.value) {
                        return true;
                    }
                }
                "input" => {
                    // OpenAI Responses API — `input` can be a bare
                    // string or an array of input items. Either way,
                    // any tainted expression in there is a hit.
                    if self.expr_taint(&p.value) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn messages_array_tainted(&self, expr: &Expression<'_>) -> bool {
        let cursor = unwrap_trivia(expr);
        match cursor {
            Expression::ArrayExpression(arr) => arr.elements.iter().any(|el| {
                el.as_expression()
                    .is_some_and(|e| self.message_entry_tainted(e))
            }),
            // The `messages` value is something other than an array
            // literal (e.g. an identifier built up earlier). Fall
            // back to whole-expression taint — over-approximates
            // but matches the conservative slice-1 stance.
            other => self.expr_taint(other),
        }
    }

    /// True if a single message-array entry has tainted content. The
    /// entry is typically `{ role: "user", content: <expr> }`.
    fn message_entry_tainted(&self, expr: &Expression<'_>) -> bool {
        let cursor = unwrap_trivia(expr);
        let Expression::ObjectExpression(obj) = cursor else {
            return self.expr_taint(expr);
        };
        for prop in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(p) = prop else {
                continue;
            };
            let PropertyKey::StaticIdentifier(key) = &p.key else {
                continue;
            };
            if key.name == "content" && self.expr_taint(&p.value) {
                return true;
            }
        }
        false
    }
}

impl<'a> Visit<'a> for PromptInjectionVisitor {
    fn visit_function(&mut self, func: &Function<'a>, _flags: stryx_ast::ScopeFlags) {
        self.enter_fn();
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
        self.check_llm_sink(call);
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
}

/// Drill through trivial wrappers (parens, TS casts, await) — the
/// AST shapes that don't change a value's identity but show up in
/// real code.
fn unwrap_trivia<'a, 'b>(expr: &'a Expression<'b>) -> &'a Expression<'b> {
    let mut cursor = expr;
    loop {
        match cursor {
            Expression::ParenthesizedExpression(p) => cursor = &p.expression,
            Expression::TSAsExpression(t) => cursor = &t.expression,
            Expression::TSNonNullExpression(t) => cursor = &t.expression,
            Expression::TSSatisfiesExpression(t) => cursor = &t.expression,
            Expression::TSTypeAssertion(t) => cursor = &t.expression,
            Expression::AwaitExpression(a) => cursor = &a.argument,
            _ => return cursor,
        }
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
