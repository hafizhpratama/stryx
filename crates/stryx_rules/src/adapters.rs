//! Stack adapter substrate ([ADR 0014]).
//!
//! Adapters teach Stryx how each TypeScript backend stack expresses
//! taint primitives — what counts as an untrusted source (e.g.
//! NestJS `@Body() dto`), what counts as a sink (e.g. `Bun.spawn`),
//! what counts as a sanitiser (e.g. `zod.safeParse`), and so on.
//! Rules stay generic; adapters contribute the stack-specific
//! patterns.
//!
//! Slice 1 of ADR 0014 — substrate-only. The trait, value types,
//! and an empty [`AdapterRegistry`] are defined. No adapter content
//! ships yet; rules do not consume the registry. First real adapter
//! lands in a later slice (`framework/nestjs`, addressing the
//! v0.3.0 dogfood gap on real NestJS code).
//!
//! [ADR 0014]: ../../../docs/decisions/0014-adapter-substrate-api.md
//!
//! # Hot-path budget
//!
//! Per [AGENTS.md], the adapter dispatch must not use
//! `Box<dyn StackAdapter>` in per-file or per-expression paths.
//! Pattern lists are `&'static [...]` slices; `EnabledAdapters`
//! holds borrows into those slices. The registry holds the
//! adapters as `&'static dyn StackAdapter` references that are
//! resolved once per scan, never per expression.
//!
//! [AGENTS.md]: ../../../AGENTS.md

use stryx_core::Severity;
use stryx_index::profile::ProjectProfile;
use stryx_taint::TaintLabel;

// =============================================================================
// Adapter identity
// =============================================================================

/// Stable namespaced adapter ID. Appears in CLI profile output, JSON
/// reports, `stryx.toml` config, and (later) GitHub Action PR comments.
///
/// Format is `<kind>/<name>` — e.g. `runtime/bun`, `framework/nestjs`,
/// `validation/zod`. Kind matches the namespace in
/// [`docs/stacks/README.md`][catalog].
///
/// [catalog]: ../../../docs/stacks/README.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AdapterId(pub &'static str);

/// Which stack dimension an adapter contributes to. Used by the
/// reporter to group adapter output by category and by
/// [`AdapterRegistry::enabled_for`] when resolving profile evidence
/// into active adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AdapterKind {
    Runtime,
    Framework,
    DataLayer,
    Validator,
    Auth,
    LlmSdk,
    Deployment,
}

// =============================================================================
// Pattern role kinds — abstract categories the analyzer dispatches on
// =============================================================================

/// What a sink contributes to taint flow analysis. Coarse-grained on
/// purpose — the per-adapter `SinkPattern` carries the syntactic
/// matchers; this enum names the *semantic* category so rules can
/// query "any DB-write sink?" without knowing every ORM's surface.
///
/// New variants are added only when a rule needs to distinguish a
/// genuinely new sink class. Adding a variant is a small surface
/// change reviewed alongside the rule that requires it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SinkKind {
    /// Structured DB write (Prisma `db.user.create`, Drizzle
    /// `db.insert`, Mongoose `model.save`, etc.). Whole-value taint
    /// in the `data` argument triggers `flow/unvalidated-body-to-db`.
    DbWrite,
    /// Raw-SQL escape hatch (Prisma `$queryRawUnsafe`, Drizzle
    /// `sql.raw`, pg `pool.query` with string arg). Triggers
    /// `flow/sql-injection`.
    RawSql,
    /// Response-body sink (`res.json`, `c.json`, `NextResponse.json`,
    /// `new Response(JSON.stringify(...))`). Triggers
    /// `flow/secret-to-response` when reached by `Secret` taint.
    Response,
    /// Outbound HTTP call (`fetch`, `axios.get`, `got`). URL argument
    /// reached by `UserInput` triggers `flow/ssrf-via-fetch`.
    Fetch,
    /// Redirect sink (`NextResponse.redirect`, `res.redirect`,
    /// `Response.redirect`, `next/navigation` `redirect`). Triggers
    /// `flow/redirect-open`.
    Redirect,
    /// Filesystem operation (`fs.readFile`, `fsPromises.writeFile`,
    /// `Bun.file`, `Bun.write`). Path argument reached by
    /// `UserInput` triggers `flow/path-traversal`.
    Filesystem,
    /// Process / shell execution (`child_process.exec`, `Bun.spawn`,
    /// `Deno.Command`). Triggers `flow/command-injection-via-exec`.
    Exec,
    /// LLM prompt sink (`openai.chat.completions.create`,
    /// `anthropic.messages.create`, `generateText`). Prompt content
    /// reached by `UserInput` triggers `flow/prompt-injection`.
    LlmPrompt,
}

/// What a sanitiser does to taint. Rules consult this to decide
/// whether a recognised call clears the relevant label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SanitizerKind {
    /// Schema parse / validate (`zod.parse`, `valibot.safeParse`,
    /// `joi.validate`). Clears `UserInput` when success is checked
    /// (for `safeParse`-style APIs) or when the call returns
    /// (for throw-on-fail APIs).
    SchemaParse,
    /// Authentication check (`getServerSession`, `auth()`,
    /// `lucia.validateRequest`, `auth.api.getSession`). Clears
    /// `UserInput` on the path past a session-required gate.
    AuthCheck,
    /// Secret redactor (`redact(...)`, `mask(...)`, `hash(...)`).
    /// Clears `Secret` taint.
    Redact,
    /// URL host allow-list check (`new URL(x)` +
    /// `ALLOWED.has(parsed.host)` early-return). Clears `UserInput`
    /// for SSRF / redirect-open rules.
    UrlAllowList,
}

/// What a guard does. Guards are sanitisers that operate on
/// control-flow rather than on individual values — e.g. middleware
/// that returns 401 before the handler runs when unauthenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GuardKind {
    /// The handler is unreachable without a valid session
    /// (middleware, decorator, wrapper). Used by
    /// `flow/auth-bypass-via-wrapper`.
    SessionRequired,
}

// =============================================================================
// AST matcher substrate
// =============================================================================

/// Syntactic shape an adapter pattern matches against. Closed enum;
/// adding a variant is a coordinated change across the enum, its
/// matcher impl, and the registry consumer — identical to the
/// [`StepKind`] growth model from [ADR 0008].
///
/// Variant set is intentionally minimal at substrate slice — only
/// the shapes the existing 11 rules already recognise inline. New
/// variants land alongside the first adapter that needs them.
///
/// [`StepKind`]: ../steps/index.html
/// [ADR 0008]: ../../../docs/decisions/0008-taint-step-trait-substrate.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AstMatcher {
    /// Member access on a bare-ident parameter binding:
    /// `req.body`, `req.query`, `req.params`, `searchParams.X`.
    /// The `receiver` matches the parameter name; `property`
    /// matches the accessed field. `property = "*"` matches any.
    MemberOnParam {
        receiver: &'static str,
        property: &'static str,
    },

    /// Method call on a known receiver: `c.req.json()`,
    /// `req.json()`. The `receiver` is the literal identifier
    /// chain (`c.req` or `req`); `method` is the called method.
    MethodCall {
        receiver: &'static str,
        method: &'static str,
    },

    /// Bare-ident call whose import target matches:
    /// `import { exec } from "child_process"` then `exec(...)`.
    /// Distinguishes a real `child_process` call from an unrelated
    /// local `exec` function with the same name.
    ImportedCall {
        module: &'static str,
        name: &'static str,
    },

    /// Decorated formal parameter: `@Body() dto: T`,
    /// `@Query() q: T`. Used by NestJS-style decorator-based
    /// parameter binding.
    DecoratedParam { decorator: &'static str },

    /// Namespace member call: `Bun.spawn(...)`,
    /// `Deno.serve(...)`, `Bun.write(...)`. Distinguishes
    /// runtime-global calls from same-named user functions.
    NamespaceCall {
        namespace: &'static str,
        member: &'static str,
    },

    /// Method call by name regardless of receiver:
    /// `<schema>.parse(value)`, `<anything>.safeParse(value)`.
    /// Used when the schema identity isn't tracked and the
    /// method name is the signal.
    MethodCallAnyReceiver { method: &'static str },

    /// Class declaration with a matching class-level decorator:
    /// `@Controller() class FooController`. Marks HTTP-handler
    /// entry-point classes for framework adapters.
    DecoratedClass { decorator: &'static str },
}

// =============================================================================
// Pattern types — what adapters contribute
// =============================================================================

/// A source pattern: AST shape that introduces taint with a
/// specific label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePattern {
    pub id: &'static str,
    pub label: TaintLabel,
    pub matchers: &'static [AstMatcher],
}

/// A sink pattern: AST shape that consumes data dangerously when
/// that data carries the relevant taint label. `severity_floor`
/// is the minimum severity for findings at this sink; rules may
/// raise but not lower it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkPattern {
    pub id: &'static str,
    pub sink: SinkKind,
    pub matchers: &'static [AstMatcher],
    pub severity_floor: Severity,
}

/// A sanitiser pattern: AST shape that clears taint from a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SanitiserPattern {
    pub id: &'static str,
    pub sanitizer: SanitizerKind,
    pub matchers: &'static [AstMatcher],
}

/// A guard pattern: control-flow gate that protects subsequent
/// code (e.g. session-required middleware).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardPattern {
    pub id: &'static str,
    pub guard: GuardKind,
    pub matchers: &'static [AstMatcher],
}

/// A propagator pattern: AST shape that carries taint through (a
/// helper, a wrapper, a projection) without acting as source or
/// sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropagatorPattern {
    pub id: &'static str,
    pub matchers: &'static [AstMatcher],
}

// =============================================================================
// StackAdapter trait
// =============================================================================

/// Contract every adapter implements. Pattern lists are `&'static`
/// so adapters compile down to constant data with zero per-scan
/// allocation. All methods default to empty — adapters override
/// only the roles they participate in (e.g. `validation/zod`
/// overrides `sanitisers()` only).
pub trait StackAdapter: Send + Sync {
    /// Stable namespaced ID (e.g. `framework/nestjs`).
    fn id(&self) -> AdapterId;

    /// Dimension this adapter contributes to.
    fn kind(&self) -> AdapterKind;

    /// Should this adapter activate for the detected project?
    ///
    /// Default: `true` when the corresponding hint family in
    /// [`ProjectProfile`] contains a `Detected` entry whose `id`
    /// matches and whose `confidence` is at least
    /// [`ENABLE_CONFIDENCE_FLOOR`] (`0.60`, per
    /// [`docs/architecture/project-profile.md`][profile-doc]).
    ///
    /// Adapters with cross-cutting applicability (e.g. a future
    /// `runtime/node` adapter that's almost always relevant for
    /// non-Bun/non-Deno projects) may override this.
    ///
    /// [profile-doc]: ../../../docs/architecture/project-profile.md
    fn is_enabled(&self, profile: &ProjectProfile) -> bool {
        is_enabled_default(self.id(), self.kind(), profile)
    }

    fn sources(&self) -> &'static [SourcePattern] {
        &[]
    }
    fn sinks(&self) -> &'static [SinkPattern] {
        &[]
    }
    fn sanitisers(&self) -> &'static [SanitiserPattern] {
        &[]
    }
    fn guards(&self) -> &'static [GuardPattern] {
        &[]
    }
    fn propagators(&self) -> &'static [PropagatorPattern] {
        &[]
    }
}

/// Confidence threshold above which a detected hint is sufficient
/// to enable its corresponding adapter by default. Matches the
/// `>= 0.60` boundary in
/// [`docs/architecture/project-profile.md`][profile-doc].
///
/// [profile-doc]: ../../../docs/architecture/project-profile.md
pub const ENABLE_CONFIDENCE_FLOOR: f32 = 0.60;

/// Default `is_enabled` resolution: check the matching hint family
/// in the profile for an entry whose id-string matches and whose
/// confidence clears the floor.
///
/// Adapter IDs are formatted `<kind>/<name>`; this function strips
/// the prefix and compares the suffix against the
/// [`serde`-canonical kebab-case name][profile-spelling] of each
/// hint variant. A `framework/nestjs` adapter matches the
/// `FrameworkHint::NestJs` profile entry (which serialises as
/// `"nestjs"` per the brand-name lock-in in
/// [`stryx_index::profile`][profile]).
///
/// [profile-spelling]: ../../../crates/stryx_index/src/profile.rs
/// [profile]: ../../../crates/stryx_index/src/profile.rs
fn is_enabled_default(id: AdapterId, kind: AdapterKind, profile: &ProjectProfile) -> bool {
    let Some((_prefix, name)) = id.0.split_once('/') else {
        return false;
    };
    match kind {
        AdapterKind::Runtime => profile
            .runtimes
            .iter()
            .any(|d| hint_serde_name(&d.id) == name && d.confidence >= ENABLE_CONFIDENCE_FLOOR),
        AdapterKind::Framework => profile
            .frameworks
            .iter()
            .any(|d| hint_serde_name(&d.id) == name && d.confidence >= ENABLE_CONFIDENCE_FLOOR),
        AdapterKind::DataLayer => profile
            .data_layers
            .iter()
            .any(|d| hint_serde_name(&d.id) == name && d.confidence >= ENABLE_CONFIDENCE_FLOOR),
        AdapterKind::Validator => profile
            .validators
            .iter()
            .any(|d| hint_serde_name(&d.id) == name && d.confidence >= ENABLE_CONFIDENCE_FLOOR),
        AdapterKind::Auth => profile
            .auth_layers
            .iter()
            .any(|d| hint_serde_name(&d.id) == name && d.confidence >= ENABLE_CONFIDENCE_FLOOR),
        AdapterKind::LlmSdk => profile
            .llm_sdks
            .iter()
            .any(|d| hint_serde_name(&d.id) == name && d.confidence >= ENABLE_CONFIDENCE_FLOOR),
        AdapterKind::Deployment => profile
            .deployments
            .iter()
            .any(|d| hint_serde_name(&d.id) == name && d.confidence >= ENABLE_CONFIDENCE_FLOOR),
    }
}

/// Serialise a hint variant to its canonical kebab-case name,
/// matching the `serde(rename_all = "kebab-case")` output in
/// [`stryx_index::profile`]. We do this via `serde_json` rather
/// than re-implementing the variant names so the two sources stay
/// in lockstep — if a new variant lands in the profile crate, the
/// adapter substrate picks it up automatically.
fn hint_serde_name<T: serde::Serialize>(hint: &T) -> String {
    serde_json::to_string(hint)
        .ok()
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_default()
}

// =============================================================================
// Registry + EnabledAdapters
// =============================================================================

/// Catalogue of every built-in adapter. Constructed once at startup
/// via [`AdapterRegistry::builtin`]; reused across rayon workers.
///
/// Currently registered: `framework/nestjs` (source patterns only).
/// More adapters land in subsequent slices.
pub struct AdapterRegistry {
    adapters: Vec<&'static dyn StackAdapter>,
}

impl AdapterRegistry {
    /// Construct the built-in registry. Adapters are registered here
    /// as they ship. Currently:
    ///
    /// - Runtime: `node`, `bun`
    /// - Framework: `express`, `hono`, `nestjs`, `next-backend`
    /// - Data layer: `prisma`, `drizzle`, `pg`
    /// - Validation: `zod`, `class-validator`
    /// - Auth: `better-auth`
    /// - LLM SDK: `openai`
    pub fn builtin() -> Self {
        static NODE: crate::adapters_node::NodeAdapter = crate::adapters_node::NodeAdapter;
        static BUN: crate::adapters_bun::BunAdapter = crate::adapters_bun::BunAdapter;
        static EXPRESS: crate::adapters_express::ExpressAdapter =
            crate::adapters_express::ExpressAdapter;
        static HONO: crate::adapters_hono::HonoAdapter = crate::adapters_hono::HonoAdapter;
        static NESTJS: crate::adapters_nestjs::NestJsAdapter =
            crate::adapters_nestjs::NestJsAdapter;
        static NEXT_BACKEND: crate::adapters_next::NextBackendAdapter =
            crate::adapters_next::NextBackendAdapter;
        static PRISMA: crate::adapters_prisma::PrismaAdapter =
            crate::adapters_prisma::PrismaAdapter;
        static DRIZZLE: crate::adapters_drizzle::DrizzleAdapter =
            crate::adapters_drizzle::DrizzleAdapter;
        static PG: crate::adapters_pg::PgAdapter = crate::adapters_pg::PgAdapter;
        static ZOD: crate::adapters_zod::ZodAdapter = crate::adapters_zod::ZodAdapter;
        static CLASS_VALIDATOR: crate::adapters_class_validator::ClassValidatorAdapter =
            crate::adapters_class_validator::ClassValidatorAdapter;
        static BETTER_AUTH: crate::adapters_better_auth::BetterAuthAdapter =
            crate::adapters_better_auth::BetterAuthAdapter;
        static OPENAI: crate::adapters_openai::OpenAiAdapter =
            crate::adapters_openai::OpenAiAdapter;
        Self {
            adapters: vec![
                &NODE,
                &BUN,
                &EXPRESS,
                &HONO,
                &NESTJS,
                &NEXT_BACKEND,
                &PRISMA,
                &DRIZZLE,
                &PG,
                &ZOD,
                &CLASS_VALIDATOR,
                &BETTER_AUTH,
                &OPENAI,
            ],
        }
    }

    /// All registered adapters, regardless of profile.
    pub fn all(&self) -> &[&'static dyn StackAdapter] {
        &self.adapters
    }

    /// Resolve which adapters apply to this project and flatten
    /// their pattern lists into a single per-role view.
    ///
    /// Called once per scan after profile detection; the resulting
    /// [`EnabledAdapters`] is shared across per-file visits.
    pub fn enabled_for(&self, profile: &ProjectProfile) -> EnabledAdapters {
        let mut active: Vec<&'static dyn StackAdapter> = Vec::new();
        let mut sources: Vec<&'static SourcePattern> = Vec::new();
        let mut sinks: Vec<&'static SinkPattern> = Vec::new();
        let mut sanitisers: Vec<&'static SanitiserPattern> = Vec::new();
        let mut guards: Vec<&'static GuardPattern> = Vec::new();
        let mut propagators: Vec<&'static PropagatorPattern> = Vec::new();
        for adapter in &self.adapters {
            if !adapter.is_enabled(profile) {
                continue;
            }
            active.push(*adapter);
            sources.extend(adapter.sources());
            sinks.extend(adapter.sinks());
            sanitisers.extend(adapter.sanitisers());
            guards.extend(adapter.guards());
            propagators.extend(adapter.propagators());
        }
        EnabledAdapters {
            active,
            sources,
            sinks,
            sanitisers,
            guards,
            propagators,
        }
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

/// Flat per-scan view of every active adapter's contributed
/// patterns. Built once after profile detection; queried per
/// expression during rule traversal.
///
/// Rules access this via `RuleContext::adapters` (added in a
/// subsequent slice once the substrate is consumed). At ADR 0014
/// step 3 the type exists but no rule reads it.
pub struct EnabledAdapters {
    /// Adapters whose `is_enabled` returned true. Order matches
    /// registry insertion order — stable across scans of the
    /// same project.
    pub active: Vec<&'static dyn StackAdapter>,
    pub sources: Vec<&'static SourcePattern>,
    pub sinks: Vec<&'static SinkPattern>,
    pub sanitisers: Vec<&'static SanitiserPattern>,
    pub guards: Vec<&'static GuardPattern>,
    pub propagators: Vec<&'static PropagatorPattern>,
}

impl EnabledAdapters {
    /// True when no adapters activated for this profile. Reporters
    /// can use this to skip adapter-related output entirely.
    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }
}

// =============================================================================
// Matcher dispatch
// =============================================================================

/// Read-only context handed to every [`AstMatcher::matches`] call.
///
/// Carries just enough state for matchers to resolve their AST shape
/// against the current file (and optionally the cross-file index).
/// Mirrors the slim contract of [`crate::steps::StepCtx`] — matchers
/// answer "does this expression match this shape?"; they do not
/// mutate visitor state.
///
/// `index` is consulted only by the [`AstMatcher::ImportedCall`]
/// variant, which needs the per-file `imports` map to distinguish a
/// real `child_process::exec` call from an unrelated local `exec`
/// binding. All other variants are pure-syntactic and ignore it.
pub struct MatcherContext<'a, 'b> {
    pub file: &'a stryx_ast::ParsedFile<'b>,
    pub index: Option<&'a stryx_index::ProjectIndex>,
}

impl AstMatcher {
    /// True iff this matcher's AST shape applies to `expr`.
    ///
    /// Dispatch is a `match` on the enum so the compiler lowers it to
    /// a jump table — per [AGENTS.md] the hot path may not use
    /// `Box<dyn Trait>`. Per-variant matching reuses the same
    /// syntactic decompositions already in
    /// [`crate::steps::sources::body`] and
    /// [`crate::steps::sinks::exec`] so the substrate is
    /// shape-equivalent to the inline recognisers it replaces.
    ///
    /// [AGENTS.md]: ../../../AGENTS.md
    pub fn matches(
        &self,
        ctx: &MatcherContext<'_, '_>,
        expr: &stryx_ast::ast::Expression<'_>,
    ) -> bool {
        use stryx_ast::ast::Expression;
        match *self {
            AstMatcher::MemberOnParam { receiver, property } => match expr {
                Expression::StaticMemberExpression(m) => {
                    expression_is_ident(&m.object, receiver)
                        && (property == "*" || m.property.name.as_str() == property)
                }
                _ => false,
            },

            AstMatcher::MethodCall { receiver, method } => match expr {
                Expression::CallExpression(call) => match &call.callee {
                    Expression::StaticMemberExpression(callee_member) => {
                        callee_member.property.name.as_str() == method
                            && expression_matches_dotted_chain(&callee_member.object, receiver)
                    }
                    _ => false,
                },
                _ => false,
            },

            AstMatcher::ImportedCall { module, name } => match expr {
                Expression::CallExpression(call) => match &call.callee {
                    Expression::Identifier(id) if id.name.as_str() == name => {
                        // Look up the bare-ident callee in the
                        // current file's import map. The matcher only
                        // fires when the import target's module
                        // specifier matches `module` exactly — this
                        // is what tells a real `child_process::exec`
                        // call apart from a local function literally
                        // named `exec`.
                        let Some(index) = ctx.index else {
                            return false;
                        };
                        let Some(summary) = index.file(&ctx.file.path) else {
                            return false;
                        };
                        summary
                            .imports
                            .get(name)
                            .map(|import_ref| import_ref.module_specifier == module)
                            .unwrap_or(false)
                    }
                    _ => false,
                },
                _ => false,
            },

            // `DecoratedParam` shape is recognised at formal-parameter
            // declaration sites (e.g. NestJS controller methods'
            // `@Body() dto: T`), not at expression sites.
            // `Expression` nodes carry no parameter decorator
            // information, so this matcher always returns `false`
            // when consulted via `matches`. Decorator-driven parameter
            // recognition is wired in a separate code path during
            // rule migration — out of scope for this slice.
            AstMatcher::DecoratedParam { .. } => false,

            AstMatcher::NamespaceCall { namespace, member } => match expr {
                Expression::CallExpression(call) => match &call.callee {
                    Expression::StaticMemberExpression(callee_member) => {
                        callee_member.property.name.as_str() == member
                            && expression_is_ident(&callee_member.object, namespace)
                    }
                    _ => false,
                },
                _ => false,
            },

            AstMatcher::MethodCallAnyReceiver { method } => match expr {
                Expression::CallExpression(call) => match &call.callee {
                    Expression::StaticMemberExpression(callee_member) => {
                        callee_member.property.name.as_str() == method
                    }
                    _ => false,
                },
                _ => false,
            },

            // Same story as `DecoratedParam`: class-level decorators
            // (`@Controller() class FooController { ... }`) attach to
            // class declarations, not to expressions. Out of scope
            // for the expression-matching slice.
            AstMatcher::DecoratedClass { .. } => false,
        }
    }
}

/// True when `expr` is a bare `Identifier` whose name equals `name`.
/// Used by the namespace/receiver shapes to recognise a single-segment
/// receiver like `Bun` or `req`.
fn expression_is_ident(expr: &stryx_ast::ast::Expression<'_>, name: &str) -> bool {
    matches!(expr, stryx_ast::ast::Expression::Identifier(id) if id.name.as_str() == name)
}

/// True when `expr` matches the dotted-identifier chain `chain`. The
/// chain is a `.`-separated string of identifiers like `"c.req"` or
/// `"req"`; the expression must be a corresponding `Identifier`
/// (single segment) or right-leaning [`StaticMemberExpression`] chain
/// rooted at an `Identifier` (multi-segment). Computed member access
/// (`a["b"]`), private fields (`a.#b`), call results, or anything
/// non-trivial fails the match — the chain syntax exists to keep the
/// recognised shape narrow.
///
/// Empty `chain` returns `false` defensively; well-formed patterns
/// never construct an empty receiver.
fn expression_matches_dotted_chain(expr: &stryx_ast::ast::Expression<'_>, chain: &str) -> bool {
    use stryx_ast::ast::Expression;
    if chain.is_empty() {
        return false;
    }
    // Walk `chain` right-to-left and `expr` outside-in: for
    // `"c.req"` against `c.req`, the SME peels `req` (matches the
    // last segment) and recurses on `c` (matches the remaining
    // single segment).
    let (head, tail) = match chain.rsplit_once('.') {
        Some((head, tail)) => (head, tail),
        None => return expression_is_ident(expr, chain),
    };
    match expr {
        Expression::StaticMemberExpression(m) => {
            m.property.name.as_str() == tail && expression_matches_dotted_chain(&m.object, head)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use stryx_index::profile::{Detected, Evidence, EvidenceKind, FrameworkHint, ProjectProfile};

    /// `builtin()` currently registers 13 adapters across six
    /// dimensions. This pin updates as new built-in adapters land.
    #[test]
    fn builtin_registry_contains_expected_adapters() {
        let reg = AdapterRegistry::builtin();
        assert_eq!(reg.all().len(), 13);
        let ids: Vec<&str> = reg.all().iter().map(|a| a.id().0).collect();
        assert!(ids.contains(&"runtime/node"));
        assert!(ids.contains(&"runtime/bun"));
        assert!(ids.contains(&"framework/express"));
        assert!(ids.contains(&"framework/hono"));
        assert!(ids.contains(&"framework/nestjs"));
        assert!(ids.contains(&"framework/next-backend"));
        assert!(ids.contains(&"data/prisma"));
        assert!(ids.contains(&"data/drizzle"));
        assert!(ids.contains(&"data/pg"));
        assert!(ids.contains(&"validation/zod"));
        assert!(ids.contains(&"validation/class-validator"));
        assert!(ids.contains(&"auth/better-auth"));
        assert!(ids.contains(&"llm/openai"));
    }

    #[test]
    fn enabled_for_empty_profile_yields_empty_view() {
        let reg = AdapterRegistry::builtin();
        let enabled = reg.enabled_for(&ProjectProfile::default());
        assert!(enabled.is_empty());
        assert_eq!(enabled.sources.len(), 0);
        assert_eq!(enabled.sinks.len(), 0);
        assert_eq!(enabled.sanitisers.len(), 0);
        assert_eq!(enabled.guards.len(), 0);
        assert_eq!(enabled.propagators.len(), 0);
    }

    #[test]
    fn is_enabled_default_matches_profile_id_and_confidence() {
        // Build a tiny profile with NestJS detected at high confidence.
        let profile = ProjectProfile {
            frameworks: vec![Detected {
                id: FrameworkHint::NestJs,
                confidence: 0.90,
                evidence: vec![Evidence {
                    kind: EvidenceKind::Dependency,
                    path: PathBuf::from("/fixture/package.json"),
                    detail: "dependencies.@nestjs/core".into(),
                    weight: 0.30,
                }],
            }],
            ..Default::default()
        };

        // Adapter ID "framework/nestjs" should match the
        // FrameworkHint::NestJs entry (which serialises as "nestjs"
        // per the brand-name lock-in in stryx_index::profile).
        assert!(is_enabled_default(
            AdapterId("framework/nestjs"),
            AdapterKind::Framework,
            &profile
        ));

        // Wrong kind: framework matcher against a runtime adapter id
        // returns false.
        assert!(!is_enabled_default(
            AdapterId("runtime/nestjs"),
            AdapterKind::Runtime,
            &profile
        ));

        // Wrong name: a different framework adapter id returns false.
        assert!(!is_enabled_default(
            AdapterId("framework/express"),
            AdapterKind::Framework,
            &profile
        ));
    }

    #[test]
    fn is_enabled_default_rejects_below_floor_confidence() {
        // Same hint at sub-floor confidence: adapter stays disabled.
        let profile = ProjectProfile {
            frameworks: vec![Detected {
                id: FrameworkHint::NestJs,
                confidence: 0.50, // below ENABLE_CONFIDENCE_FLOOR (0.60)
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!is_enabled_default(
            AdapterId("framework/nestjs"),
            AdapterKind::Framework,
            &profile
        ));
    }

    #[test]
    fn adapter_id_malformed_returns_false() {
        // An id missing the "kind/" prefix can't match any hint
        // family — defensive check on the split_once branch.
        let profile = ProjectProfile::default();
        assert!(!is_enabled_default(
            AdapterId("nestjs"),
            AdapterKind::Framework,
            &profile
        ));
    }
}

#[cfg(test)]
mod matcher_tests {
    //! Per-variant tests for [`AstMatcher::matches`].
    //!
    //! Each test parses a tiny TS snippet via [`stryx_ast::parse`],
    //! pulls out the expression of interest from the AST, and asserts
    //! the matcher fires / does not fire as documented in
    //! [ADR 0014](../../../docs/decisions/0014-adapter-substrate-api.md).
    //!
    //! The fixture model is deliberately minimal — single-statement
    //! programs that materialise the expression shape under test —
    //! so failures point at the matcher, not at AST shape drift.
    //! When a matcher gains a new sub-shape, the test for that
    //! variant grows a positive and a negative case for the new
    //! shape, never a parallel test module.
    use super::*;
    use std::path::{Path, PathBuf};
    use stryx_ast::ast::{Expression, Statement};
    use stryx_ast::{Allocator, ParsedFile, parse};
    use stryx_index::{FileSummary, ImportRef, ProjectIndex};

    /// Pull the first expression out of a `const x = <expr>;` or
    /// `<expr>;` program. Panics on shape mismatch — the snippets
    /// are author-controlled, so an unexpected AST is a fixture bug.
    fn first_expression<'a>(parsed: &'a ParsedFile<'_>) -> &'a Expression<'a> {
        let stmt = parsed
            .program
            .body
            .first()
            .expect("snippet has at least one statement");
        match stmt {
            Statement::VariableDeclaration(decl) => decl
                .declarations
                .first()
                .and_then(|d| d.init.as_ref())
                .expect("declarator with init"),
            Statement::ExpressionStatement(es) => &es.expression,
            _ => panic!("snippet must parse to a VariableDeclaration or ExpressionStatement"),
        }
    }

    /// Convenience: parse `source` into an allocator-owned
    /// [`ParsedFile`] at a virtual path.
    fn parse_snippet<'a>(allocator: &'a Allocator, source: &'a str) -> ParsedFile<'a> {
        parse(allocator, Path::new("/virt/file.ts"), source).expect("parse")
    }

    /// Build a no-index [`MatcherContext`] borrowed from `file`. The
    /// `index: None` arm is what most matcher variants need — only
    /// [`AstMatcher::ImportedCall`] consults the index, and those
    /// tests build their own `MatcherContext` inline with a real
    /// [`ProjectIndex`].
    fn matcher_ctx<'a, 'b>(file: &'a ParsedFile<'b>) -> MatcherContext<'a, 'b> {
        MatcherContext { file, index: None }
    }

    // ── MemberOnParam ───────────────────────────────────────────────

    #[test]
    fn member_on_param_matches_req_body() {
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "const x = req.body;");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::MemberOnParam {
            receiver: "req",
            property: "body",
        };
        assert!(matcher.matches(&ctx, expr));
    }

    #[test]
    fn member_on_param_rejects_wrong_receiver() {
        // `other.body` must not match `req.*`.
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "const x = other.body;");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::MemberOnParam {
            receiver: "req",
            property: "body",
        };
        assert!(!matcher.matches(&ctx, expr));
    }

    #[test]
    fn member_on_param_wildcard_property_matches_any_field() {
        // `property: "*"` is the "any field on this receiver" form,
        // used for shapes like `searchParams.X` where every property
        // is URL-derived.
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "const x = req.weird_custom_field;");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::MemberOnParam {
            receiver: "req",
            property: "*",
        };
        assert!(matcher.matches(&ctx, expr));
    }

    #[test]
    fn member_on_param_rejects_wrong_property_when_named() {
        // Named property must match exactly — `req.foo` does not
        // match `req.body`.
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "const x = req.foo;");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::MemberOnParam {
            receiver: "req",
            property: "body",
        };
        assert!(!matcher.matches(&ctx, expr));
    }

    // ── MethodCall ──────────────────────────────────────────────────

    #[test]
    fn method_call_matches_chained_receiver() {
        // `c.req.json()` — two-segment receiver chain, exactly the
        // Hono context shape called out in the ADR.
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "c.req.json();");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::MethodCall {
            receiver: "c.req",
            method: "json",
        };
        assert!(matcher.matches(&ctx, expr));
    }

    #[test]
    fn method_call_matches_single_segment_receiver() {
        // `req.json()` — single-ident receiver, the bare-handler case.
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "req.json();");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::MethodCall {
            receiver: "req",
            method: "json",
        };
        assert!(matcher.matches(&ctx, expr));
    }

    #[test]
    fn method_call_rejects_wrong_method() {
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "c.req.text();");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::MethodCall {
            receiver: "c.req",
            method: "json",
        };
        assert!(!matcher.matches(&ctx, expr));
    }

    #[test]
    fn method_call_rejects_wrong_receiver() {
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "ctx.req.json();");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::MethodCall {
            receiver: "c.req",
            method: "json",
        };
        assert!(!matcher.matches(&ctx, expr));
    }

    // ── ImportedCall ────────────────────────────────────────────────

    #[test]
    fn imported_call_returns_false_without_index() {
        // Per ADR 0014: when `ctx.index` is `None`, an `ImportedCall`
        // matcher cannot resolve the import target and must abstain.
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "exec('ls');");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::ImportedCall {
            module: "child_process",
            name: "exec",
        };
        assert!(!matcher.matches(&ctx, expr));
    }

    #[test]
    fn imported_call_matches_when_import_resolves_to_module() {
        // Build a real ProjectIndex with the file's `imports` map
        // populated so the matcher can verify `exec` came from
        // `child_process`. Parsing the snippet here doesn't populate
        // the index (the index is built by the extract pass, not by
        // `parse`), so we hand-roll the summary to mirror what the
        // pass would produce for `import { exec } from "child_process"`.
        let alloc = Allocator::default();
        let file_path = PathBuf::from("/virt/file.ts");
        let source = "exec('ls');";
        let parsed = parse(&alloc, &file_path, source).expect("parse");
        let expr = first_expression(&parsed);

        let mut summary = FileSummary {
            path: file_path.clone(),
            ..Default::default()
        };
        summary.imports.insert(
            "exec".into(),
            ImportRef {
                module_specifier: "child_process".into(),
                imported_name: "exec".into(),
            },
        );
        let mut index = ProjectIndex::new();
        index.insert_file(summary);

        let ctx = MatcherContext {
            file: &parsed,
            index: Some(&index),
        };

        let matcher = AstMatcher::ImportedCall {
            module: "child_process",
            name: "exec",
        };
        assert!(matcher.matches(&ctx, expr));
    }

    #[test]
    fn imported_call_rejects_wrong_module() {
        // Same shape, but the import comes from an unrelated module —
        // a local helper that happens to be named `exec`. Stryx must
        // not raise a `child_process` finding.
        let alloc = Allocator::default();
        let file_path = PathBuf::from("/virt/file.ts");
        let parsed = parse(&alloc, &file_path, "exec('ls');").expect("parse");
        let expr = first_expression(&parsed);

        let mut summary = FileSummary {
            path: file_path.clone(),
            ..Default::default()
        };
        summary.imports.insert(
            "exec".into(),
            ImportRef {
                module_specifier: "./my-local-helpers".into(),
                imported_name: "exec".into(),
            },
        );
        let mut index = ProjectIndex::new();
        index.insert_file(summary);

        let ctx = MatcherContext {
            file: &parsed,
            index: Some(&index),
        };

        let matcher = AstMatcher::ImportedCall {
            module: "child_process",
            name: "exec",
        };
        assert!(!matcher.matches(&ctx, expr));
    }

    #[test]
    fn imported_call_rejects_member_call_callee() {
        // `cp.exec('ls')` is not a bare-ident call — `ImportedCall`
        // shape is specifically the destructured-import case.
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "cp.exec('ls');");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::ImportedCall {
            module: "child_process",
            name: "exec",
        };
        assert!(!matcher.matches(&ctx, expr));
    }

    // ── NamespaceCall ───────────────────────────────────────────────

    #[test]
    fn namespace_call_matches_bun_spawn() {
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "Bun.spawn(['ls']);");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::NamespaceCall {
            namespace: "Bun",
            member: "spawn",
        };
        assert!(matcher.matches(&ctx, expr));
    }

    #[test]
    fn namespace_call_rejects_wrong_namespace() {
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "Deno.spawn(['ls']);");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::NamespaceCall {
            namespace: "Bun",
            member: "spawn",
        };
        assert!(!matcher.matches(&ctx, expr));
    }

    #[test]
    fn namespace_call_rejects_chained_receiver() {
        // Namespace shape is single-ident only — `globalThis.Bun.spawn()`
        // is not a `NamespaceCall` match because the receiver is not a
        // bare identifier. Adapters that need that shape can either
        // use `MethodCall` with a dotted receiver or add a dedicated
        // variant in a future slice.
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "globalThis.Bun.spawn(['ls']);");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::NamespaceCall {
            namespace: "Bun",
            member: "spawn",
        };
        assert!(!matcher.matches(&ctx, expr));
    }

    // ── MethodCallAnyReceiver ───────────────────────────────────────

    #[test]
    fn method_call_any_receiver_matches_parse() {
        // The schema-parse shape — receiver identity doesn't matter,
        // only the called method name.
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "schema.parse(x);");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::MethodCallAnyReceiver { method: "parse" };
        assert!(matcher.matches(&ctx, expr));
    }

    #[test]
    fn method_call_any_receiver_matches_any_receiver() {
        // Same call shape with a completely different receiver name —
        // still matches.
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "UserSchema.parse(input);");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::MethodCallAnyReceiver { method: "parse" };
        assert!(matcher.matches(&ctx, expr));
    }

    #[test]
    fn method_call_any_receiver_rejects_wrong_method() {
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "schema.other(x);");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::MethodCallAnyReceiver { method: "parse" };
        assert!(!matcher.matches(&ctx, expr));
    }

    #[test]
    fn method_call_any_receiver_rejects_bare_ident_call() {
        // Bare-ident `parse(x)` is not a member call — the matcher
        // explicitly requires a `<receiver>.<method>(...)` shape.
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "parse(x);");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::MethodCallAnyReceiver { method: "parse" };
        assert!(!matcher.matches(&ctx, expr));
    }

    // ── DecoratedParam / DecoratedClass ─────────────────────────────

    #[test]
    fn decorated_param_always_false_on_expressions() {
        // `Expression` nodes don't carry parameter decorators —
        // recognition happens at the parameter declaration site in a
        // separate code path. Documented in the matcher impl.
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "const x = req.body;");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::DecoratedParam { decorator: "Body" };
        assert!(!matcher.matches(&ctx, expr));
    }

    #[test]
    fn decorated_class_always_false_on_expressions() {
        // Class-level decorators attach to class declarations, not
        // expressions. Documented in the matcher impl.
        let alloc = Allocator::default();
        let parsed = parse_snippet(&alloc, "const x = req.body;");
        let expr = first_expression(&parsed);
        let ctx = matcher_ctx(&parsed);
        let matcher = AstMatcher::DecoratedClass {
            decorator: "Controller",
        };
        assert!(!matcher.matches(&ctx, expr));
    }
}
