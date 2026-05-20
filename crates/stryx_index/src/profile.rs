//! `ProjectProfile` — stack detection for the user's TypeScript backend.
//!
//! Phase 1 ships the cheap evidence pass only: detect runtime / framework /
//! data layer / validator / auth / LLM SDK / deployment from package.json,
//! lockfiles, and a small set of config files. Source-evidence collection
//! (imports, globals, call expressions, decorators) and `WorkspaceProfile`
//! for monorepos are deferred to a later phase.
//!
//! See `docs/architecture/project-profile.md` and ADR 0013.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

mod detect;

pub use detect::detect;

/// What runtime / framework / etc. stack a project uses, plus the
/// evidence that produced each detection. Empty when no recognisable
/// stack is present (e.g. plain TS library, empty fixture).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ProjectProfile {
    #[serde(default)]
    pub language: LanguageHint,
    #[serde(default)]
    pub runtimes: Vec<Detected<RuntimeHint>>,
    #[serde(default)]
    pub frameworks: Vec<Detected<FrameworkHint>>,
    #[serde(default)]
    pub data_layers: Vec<Detected<DataLayerHint>>,
    #[serde(default)]
    pub validators: Vec<Detected<ValidatorHint>>,
    #[serde(default)]
    pub auth_layers: Vec<Detected<AuthHint>>,
    #[serde(default)]
    pub llm_sdks: Vec<Detected<LlmSdkHint>>,
    #[serde(default)]
    pub deployments: Vec<Detected<DeploymentHint>>,
}

impl ProjectProfile {
    /// True when every hint family is empty and the language is unknown.
    /// Reporters skip the profile block when this is true.
    pub fn is_empty(&self) -> bool {
        matches!(self.language, LanguageHint::Unknown)
            && self.runtimes.is_empty()
            && self.frameworks.is_empty()
            && self.data_layers.is_empty()
            && self.validators.is_empty()
            && self.auth_layers.is_empty()
            && self.llm_sdks.is_empty()
            && self.deployments.is_empty()
    }
}

/// A single detected hint with the evidence that produced it and a
/// combined confidence score in `[0.0, 1.0]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Detected<T> {
    pub id: T,
    pub confidence: f32,
    pub evidence: Vec<Evidence>,
}

/// One piece of evidence that contributed to a detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub path: PathBuf,
    pub detail: String,
    pub weight: f32,
}

/// Source of an evidence entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    PackageManager,
    Dependency,
    DevDependency,
    PackageScript,
    Lockfile,
    ConfigFile,
    TsConfig,
}

#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(rename_all = "kebab-case")]
pub enum LanguageHint {
    #[default]
    Unknown,
    #[serde(rename = "javascript")]
    JavaScript,
    #[serde(rename = "typescript")]
    TypeScript,
    Mixed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeHint {
    Node,
    Bun,
    Deno,
    CloudflareWorkers,
    VercelEdge,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum FrameworkHint {
    NextBackend,
    Hono,
    Express,
    Fastify,
    #[serde(rename = "nestjs")]
    NestJs,
    Elysia,
    Oak,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum DataLayerHint {
    Prisma,
    Drizzle,
    Kysely,
    Knex,
    Pg,
    Mysql2,
    BunSqlite,
    BunSql,
    Mongoose,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ValidatorHint {
    Zod,
    Valibot,
    Yup,
    Joi,
    Ajv,
    #[serde(rename = "arktype")]
    ArkType,
    #[serde(rename = "typebox")]
    TypeBox,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum AuthHint {
    BetterAuth,
    AuthJs,
    Clerk,
    SupabaseAuth,
    Lucia,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum LlmSdkHint {
    #[serde(rename = "openai")]
    OpenAi,
    Anthropic,
    VercelAiSdk,
    #[serde(rename = "langchain")]
    LangChain,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentHint {
    Vercel,
    Cloudflare,
    AwsLambda,
    Netlify,
    FlyIo,
    Docker,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock in the public JSON spelling of hint variants. The default
    /// kebab-case rule splits CamelCase on every capital, which turns
    /// proper-noun brand names like `TypeScript` and `OpenAi` into the
    /// wrong strings (`type-script`, `open-ai`). Each variant below uses
    /// `#[serde(rename = ...)]` to override; this test guards the
    /// outputs from regressing.
    #[test]
    fn brand_name_variants_serialize_to_canonical_strings() {
        let cases = [
            (
                serde_json::to_string(&LanguageHint::TypeScript).unwrap(),
                "\"typescript\"",
            ),
            (
                serde_json::to_string(&LanguageHint::JavaScript).unwrap(),
                "\"javascript\"",
            ),
            (
                serde_json::to_string(&FrameworkHint::NestJs).unwrap(),
                "\"nestjs\"",
            ),
            (
                serde_json::to_string(&FrameworkHint::NextBackend).unwrap(),
                "\"next-backend\"",
            ),
            (
                serde_json::to_string(&ValidatorHint::TypeBox).unwrap(),
                "\"typebox\"",
            ),
            (
                serde_json::to_string(&ValidatorHint::ArkType).unwrap(),
                "\"arktype\"",
            ),
            (
                serde_json::to_string(&LlmSdkHint::OpenAi).unwrap(),
                "\"openai\"",
            ),
            (
                serde_json::to_string(&LlmSdkHint::LangChain).unwrap(),
                "\"langchain\"",
            ),
            (
                serde_json::to_string(&AuthHint::BetterAuth).unwrap(),
                "\"better-auth\"",
            ),
            (
                serde_json::to_string(&AuthHint::AuthJs).unwrap(),
                "\"auth-js\"",
            ),
            (
                serde_json::to_string(&RuntimeHint::CloudflareWorkers).unwrap(),
                "\"cloudflare-workers\"",
            ),
        ];
        for (got, want) in &cases {
            assert_eq!(got, want, "JSON spelling regressed");
        }
    }

    #[test]
    fn is_empty_matches_default() {
        assert!(ProjectProfile::default().is_empty());
    }
}
