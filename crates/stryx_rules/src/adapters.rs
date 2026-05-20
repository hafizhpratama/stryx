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
/// At substrate slice (ADR 0014 step 2), the registry is empty.
/// First adapters land in a later slice.
pub struct AdapterRegistry {
    adapters: Vec<&'static dyn StackAdapter>,
}

impl AdapterRegistry {
    /// Construct the built-in registry. Empty at the substrate
    /// slice — adapters will be registered here as they ship.
    pub fn builtin() -> Self {
        Self {
            adapters: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use stryx_index::profile::{Detected, Evidence, EvidenceKind, FrameworkHint, ProjectProfile};

    /// At substrate slice, `builtin()` ships no adapters. This test
    /// pins that fact — when adapters start landing in later
    /// slices, this test should fail and be updated alongside the
    /// adapter registration.
    #[test]
    fn builtin_registry_is_empty_at_substrate_slice() {
        let reg = AdapterRegistry::builtin();
        assert_eq!(reg.all().len(), 0);
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
