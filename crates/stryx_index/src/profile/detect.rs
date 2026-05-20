//! Cheap-pass stack detector. Reads `package.json`, lockfiles, and a
//! few config files. Never parses source. Never makes network calls.
//! Errors are logged at `warn` and never propagated — a malformed
//! workspace returns an empty profile rather than failing the scan.

use crate::jsonc::strip_jsonc;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::{
    AuthHint, DataLayerHint, DeploymentHint, Detected, Evidence, EvidenceKind, FrameworkHint,
    LanguageHint, LlmSdkHint, ProjectProfile, RuntimeHint, ValidatorHint,
};

// Evidence weights per docs/architecture/project-profile.md. Capped at
// 1.0 when summed per hint.
const W_CONFIG_FILE: f32 = 0.40;
const W_LOCKFILE: f32 = 0.35;
const W_PACKAGE_MANAGER: f32 = 0.35;
const W_DEPENDENCY: f32 = 0.30;
const W_SCRIPT: f32 = 0.20;

/// Build a `ProjectProfile` from local workspace contents. Returns an
/// empty profile if `path` isn't a directory we can read or contains
/// no recognisable stack evidence.
pub fn detect(path: &Path) -> ProjectProfile {
    let root = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(Path::new(".")).to_path_buf()
    };

    let pkg = read_package_json(&root);

    ProjectProfile {
        language: detect_language(&root, pkg.as_ref()),
        runtimes: detect_runtimes(&root, pkg.as_ref()),
        frameworks: detect_frameworks(pkg.as_ref(), &root),
        data_layers: detect_data_layers(pkg.as_ref()),
        validators: detect_validators(pkg.as_ref()),
        auth_layers: detect_auth(pkg.as_ref()),
        llm_sdks: detect_llm(pkg.as_ref()),
        deployments: detect_deployments(&root),
    }
}

/// Parsed view of the workspace's `package.json`. Missing keys are `None`.
struct PackageJson {
    path: PathBuf,
    dependencies: HashMap<String, String>,
    dev_dependencies: HashMap<String, String>,
    scripts: HashMap<String, String>,
    package_manager: Option<String>,
    engines_node: Option<String>,
    type_module: bool,
}

fn read_package_json(root: &Path) -> Option<PackageJson> {
    let path = root.join("package.json");
    if !path.exists() {
        return None;
    }
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(?path, %err, "failed to read package.json");
            return None;
        }
    };
    let cleaned = strip_jsonc(&raw);
    let value: Value = match serde_json::from_str(&cleaned) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(?path, %err, "failed to parse package.json");
            return None;
        }
    };
    Some(PackageJson {
        path,
        dependencies: as_str_map(value.get("dependencies")),
        dev_dependencies: as_str_map(value.get("devDependencies")),
        scripts: as_str_map(value.get("scripts")),
        package_manager: value
            .get("packageManager")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        engines_node: value
            .pointer("/engines/node")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        type_module: value.get("type").and_then(|v| v.as_str()) == Some("module"),
    })
}

fn as_str_map(value: Option<&Value>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(obj) = value.and_then(|v| v.as_object()) {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                out.insert(k.clone(), s.to_string());
            }
        }
    }
    out
}

fn detect_language(root: &Path, pkg: Option<&PackageJson>) -> LanguageHint {
    let has_tsconfig = root.join("tsconfig.json").exists();
    let has_jsconfig = root.join("jsconfig.json").exists();
    let has_ts_dep = pkg
        .map(|p| {
            p.dependencies.contains_key("typescript")
                || p.dev_dependencies.contains_key("typescript")
        })
        .unwrap_or(false);
    if has_tsconfig || has_ts_dep {
        LanguageHint::TypeScript
    } else if has_jsconfig || pkg.is_some_and(|p| p.type_module) {
        LanguageHint::JavaScript
    } else {
        LanguageHint::Unknown
    }
}

fn detect_runtimes(root: &Path, pkg: Option<&PackageJson>) -> Vec<Detected<RuntimeHint>> {
    let mut acc: HashMap<RuntimeHint, Vec<Evidence>> = HashMap::new();

    // Bun
    if root.join("bun.lock").exists() {
        push_ev(
            &mut acc,
            RuntimeHint::Bun,
            EvidenceKind::Lockfile,
            root.join("bun.lock"),
            "bun.lock",
            W_LOCKFILE,
        );
    }
    if root.join("bun.lockb").exists() {
        push_ev(
            &mut acc,
            RuntimeHint::Bun,
            EvidenceKind::Lockfile,
            root.join("bun.lockb"),
            "bun.lockb",
            W_LOCKFILE,
        );
    }
    if root.join("bunfig.toml").exists() {
        push_ev(
            &mut acc,
            RuntimeHint::Bun,
            EvidenceKind::ConfigFile,
            root.join("bunfig.toml"),
            "bunfig.toml",
            W_CONFIG_FILE,
        );
    }
    if let Some(p) = pkg
        && let Some(pm) = &p.package_manager
        && pm.starts_with("bun@")
    {
        push_ev(
            &mut acc,
            RuntimeHint::Bun,
            EvidenceKind::PackageManager,
            p.path.clone(),
            format!("packageManager: \"{pm}\""),
            W_PACKAGE_MANAGER,
        );
    }
    if let Some(p) = pkg {
        for (name, src) in &p.scripts {
            if src.starts_with("bun ") || src.contains(" bun ") || src.starts_with("bunx ") {
                push_ev(
                    &mut acc,
                    RuntimeHint::Bun,
                    EvidenceKind::PackageScript,
                    p.path.clone(),
                    format!("scripts.{name}: \"{src}\""),
                    W_SCRIPT,
                );
                break;
            }
        }
    }

    // Node — package-lock.json, pnpm-lock.yaml, yarn.lock all imply Node.
    // engines.node is the strongest single signal.
    let node_lockfiles = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"];
    for lf in node_lockfiles {
        if root.join(lf).exists() {
            push_ev(
                &mut acc,
                RuntimeHint::Node,
                EvidenceKind::Lockfile,
                root.join(lf),
                lf,
                W_LOCKFILE,
            );
        }
    }
    if let Some(p) = pkg
        && let Some(eng) = &p.engines_node
    {
        push_ev(
            &mut acc,
            RuntimeHint::Node,
            EvidenceKind::PackageManager,
            p.path.clone(),
            format!("engines.node: \"{eng}\""),
            W_PACKAGE_MANAGER,
        );
    }
    if let Some(p) = pkg
        && let Some(pm) = &p.package_manager
        && (pm.starts_with("pnpm@") || pm.starts_with("yarn@") || pm.starts_with("npm@"))
    {
        push_ev(
            &mut acc,
            RuntimeHint::Node,
            EvidenceKind::PackageManager,
            p.path.clone(),
            format!("packageManager: \"{pm}\""),
            W_PACKAGE_MANAGER,
        );
    }

    // Cloudflare Workers
    if root.join("wrangler.toml").exists() {
        push_ev(
            &mut acc,
            RuntimeHint::CloudflareWorkers,
            EvidenceKind::ConfigFile,
            root.join("wrangler.toml"),
            "wrangler.toml",
            W_CONFIG_FILE,
        );
    }
    if root.join("wrangler.jsonc").exists() {
        push_ev(
            &mut acc,
            RuntimeHint::CloudflareWorkers,
            EvidenceKind::ConfigFile,
            root.join("wrangler.jsonc"),
            "wrangler.jsonc",
            W_CONFIG_FILE,
        );
    }
    if pkg.is_some_and(|p| {
        p.dev_dependencies.contains_key("@cloudflare/workers-types")
            || p.dependencies.contains_key("@cloudflare/workers-types")
    }) {
        let pkg_path = pkg.unwrap().path.clone();
        push_ev(
            &mut acc,
            RuntimeHint::CloudflareWorkers,
            EvidenceKind::DevDependency,
            pkg_path,
            "@cloudflare/workers-types",
            W_DEPENDENCY,
        );
    }

    // Deno
    if root.join("deno.json").exists() || root.join("deno.jsonc").exists() {
        let path = if root.join("deno.json").exists() {
            root.join("deno.json")
        } else {
            root.join("deno.jsonc")
        };
        push_ev(
            &mut acc,
            RuntimeHint::Deno,
            EvidenceKind::ConfigFile,
            path,
            "deno config",
            W_CONFIG_FILE,
        );
    }
    if root.join("deno.lock").exists() {
        push_ev(
            &mut acc,
            RuntimeHint::Deno,
            EvidenceKind::Lockfile,
            root.join("deno.lock"),
            "deno.lock",
            W_LOCKFILE,
        );
    }

    finalize(acc)
}

fn detect_frameworks(pkg: Option<&PackageJson>, root: &Path) -> Vec<Detected<FrameworkHint>> {
    let mut acc: HashMap<FrameworkHint, Vec<Evidence>> = HashMap::new();
    let Some(pkg) = pkg else { return Vec::new() };

    push_dep_for(&mut acc, pkg, "next", FrameworkHint::NextBackend);
    push_dep_for(&mut acc, pkg, "hono", FrameworkHint::Hono);
    push_dep_for(&mut acc, pkg, "express", FrameworkHint::Express);
    push_dep_for(&mut acc, pkg, "fastify", FrameworkHint::Fastify);
    push_dep_for(&mut acc, pkg, "elysia", FrameworkHint::Elysia);
    push_dep_for(&mut acc, pkg, "@oak/oak", FrameworkHint::Oak);
    // NestJS — every real NestJS app pulls in multiple `@nestjs/*`
    // packages. Each contributes evidence weight, so confidence
    // accumulates well above any underlying transport framework
    // (Express/Fastify) that NestJS happens to use internally. This
    // avoids the false-positive where NestJS apps were detected as
    // Express because both showed at single-package weight.
    for nest_pkg in [
        "@nestjs/core",
        "@nestjs/common",
        "@nestjs/platform-express",
        "@nestjs/platform-fastify",
        "@nestjs/config",
        "@nestjs/mapped-types",
        "@nestjs/swagger",
        "@nestjs/cli",
    ] {
        push_dep_for(&mut acc, pkg, nest_pkg, FrameworkHint::NestJs);
    }

    // Next.js — `app/` or `pages/` directory at the scan root reinforces.
    if pkg.dependencies.contains_key("next") || pkg.dev_dependencies.contains_key("next") {
        for sub in ["app", "pages", "src/app", "src/pages"] {
            if root.join(sub).is_dir() {
                push_ev(
                    &mut acc,
                    FrameworkHint::NextBackend,
                    EvidenceKind::ConfigFile,
                    root.join(sub),
                    format!("{sub}/ directory"),
                    W_CONFIG_FILE,
                );
                break;
            }
        }
    }

    finalize(acc)
}

fn detect_data_layers(pkg: Option<&PackageJson>) -> Vec<Detected<DataLayerHint>> {
    let mut acc: HashMap<DataLayerHint, Vec<Evidence>> = HashMap::new();
    let Some(pkg) = pkg else { return Vec::new() };

    push_dep_for(&mut acc, pkg, "@prisma/client", DataLayerHint::Prisma);
    push_dep_for(&mut acc, pkg, "drizzle-orm", DataLayerHint::Drizzle);
    push_dep_for(&mut acc, pkg, "kysely", DataLayerHint::Kysely);
    push_dep_for(&mut acc, pkg, "knex", DataLayerHint::Knex);
    push_dep_for(&mut acc, pkg, "pg", DataLayerHint::Pg);
    push_dep_for(&mut acc, pkg, "mysql2", DataLayerHint::Mysql2);
    push_dep_for(&mut acc, pkg, "mongoose", DataLayerHint::Mongoose);

    finalize(acc)
}

fn detect_validators(pkg: Option<&PackageJson>) -> Vec<Detected<ValidatorHint>> {
    let mut acc: HashMap<ValidatorHint, Vec<Evidence>> = HashMap::new();
    let Some(pkg) = pkg else { return Vec::new() };

    push_dep_for(&mut acc, pkg, "zod", ValidatorHint::Zod);
    push_dep_for(&mut acc, pkg, "valibot", ValidatorHint::Valibot);
    push_dep_for(&mut acc, pkg, "yup", ValidatorHint::Yup);
    push_dep_for(&mut acc, pkg, "joi", ValidatorHint::Joi);
    push_dep_for(&mut acc, pkg, "ajv", ValidatorHint::Ajv);
    push_dep_for(&mut acc, pkg, "arktype", ValidatorHint::ArkType);
    push_dep_for(&mut acc, pkg, "@sinclair/typebox", ValidatorHint::TypeBox);

    finalize(acc)
}

fn detect_auth(pkg: Option<&PackageJson>) -> Vec<Detected<AuthHint>> {
    let mut acc: HashMap<AuthHint, Vec<Evidence>> = HashMap::new();
    let Some(pkg) = pkg else { return Vec::new() };

    push_dep_for(&mut acc, pkg, "better-auth", AuthHint::BetterAuth);
    push_dep_for(&mut acc, pkg, "next-auth", AuthHint::AuthJs);
    push_dep_for(&mut acc, pkg, "@auth/core", AuthHint::AuthJs);
    push_dep_for(&mut acc, pkg, "@clerk/nextjs", AuthHint::Clerk);
    push_dep_for(&mut acc, pkg, "@clerk/clerk-sdk-node", AuthHint::Clerk);
    push_dep_for(
        &mut acc,
        pkg,
        "@supabase/supabase-js",
        AuthHint::SupabaseAuth,
    );
    push_dep_for(&mut acc, pkg, "lucia", AuthHint::Lucia);

    finalize(acc)
}

fn detect_llm(pkg: Option<&PackageJson>) -> Vec<Detected<LlmSdkHint>> {
    let mut acc: HashMap<LlmSdkHint, Vec<Evidence>> = HashMap::new();
    let Some(pkg) = pkg else { return Vec::new() };

    push_dep_for(&mut acc, pkg, "openai", LlmSdkHint::OpenAi);
    push_dep_for(&mut acc, pkg, "@anthropic-ai/sdk", LlmSdkHint::Anthropic);
    push_dep_for(&mut acc, pkg, "ai", LlmSdkHint::VercelAiSdk);
    push_dep_for(&mut acc, pkg, "langchain", LlmSdkHint::LangChain);
    push_dep_for(&mut acc, pkg, "@langchain/core", LlmSdkHint::LangChain);

    finalize(acc)
}

fn detect_deployments(root: &Path) -> Vec<Detected<DeploymentHint>> {
    let mut acc: HashMap<DeploymentHint, Vec<Evidence>> = HashMap::new();

    if root.join("vercel.json").exists() {
        push_ev(
            &mut acc,
            DeploymentHint::Vercel,
            EvidenceKind::ConfigFile,
            root.join("vercel.json"),
            "vercel.json",
            W_CONFIG_FILE,
        );
    }
    if root.join("wrangler.toml").exists() {
        push_ev(
            &mut acc,
            DeploymentHint::Cloudflare,
            EvidenceKind::ConfigFile,
            root.join("wrangler.toml"),
            "wrangler.toml",
            W_CONFIG_FILE,
        );
    }
    if root.join("wrangler.jsonc").exists() {
        push_ev(
            &mut acc,
            DeploymentHint::Cloudflare,
            EvidenceKind::ConfigFile,
            root.join("wrangler.jsonc"),
            "wrangler.jsonc",
            W_CONFIG_FILE,
        );
    }
    if root.join("netlify.toml").exists() {
        push_ev(
            &mut acc,
            DeploymentHint::Netlify,
            EvidenceKind::ConfigFile,
            root.join("netlify.toml"),
            "netlify.toml",
            W_CONFIG_FILE,
        );
    }
    if root.join("fly.toml").exists() {
        push_ev(
            &mut acc,
            DeploymentHint::FlyIo,
            EvidenceKind::ConfigFile,
            root.join("fly.toml"),
            "fly.toml",
            W_CONFIG_FILE,
        );
    }
    if root.join("Dockerfile").exists() {
        push_ev(
            &mut acc,
            DeploymentHint::Docker,
            EvidenceKind::ConfigFile,
            root.join("Dockerfile"),
            "Dockerfile",
            W_CONFIG_FILE,
        );
    }
    if root.join("serverless.yml").exists() {
        push_ev(
            &mut acc,
            DeploymentHint::AwsLambda,
            EvidenceKind::ConfigFile,
            root.join("serverless.yml"),
            "serverless.yml",
            W_CONFIG_FILE,
        );
    }

    finalize(acc)
}

fn push_dep_for<T: std::hash::Hash + Eq>(
    acc: &mut HashMap<T, Vec<Evidence>>,
    pkg: &PackageJson,
    dep_name: &str,
    hint: T,
) {
    if pkg.dependencies.contains_key(dep_name) {
        push_ev(
            acc,
            hint,
            EvidenceKind::Dependency,
            pkg.path.clone(),
            format!("dependencies.{dep_name}"),
            W_DEPENDENCY,
        );
    } else if pkg.dev_dependencies.contains_key(dep_name) {
        push_ev(
            acc,
            hint,
            EvidenceKind::DevDependency,
            pkg.path.clone(),
            format!("devDependencies.{dep_name}"),
            W_DEPENDENCY,
        );
    }
}

fn push_ev<T: std::hash::Hash + Eq>(
    acc: &mut HashMap<T, Vec<Evidence>>,
    hint: T,
    kind: EvidenceKind,
    path: PathBuf,
    detail: impl Into<String>,
    weight: f32,
) {
    acc.entry(hint).or_default().push(Evidence {
        kind,
        path,
        detail: detail.into(),
        weight,
    });
}

fn finalize<T: Copy + Ord>(acc: HashMap<T, Vec<Evidence>>) -> Vec<Detected<T>> {
    let mut out: Vec<Detected<T>> = acc
        .into_iter()
        .map(|(id, evidence)| Detected {
            id,
            confidence: evidence.iter().map(|e| e.weight).sum::<f32>().min(1.0),
            evidence,
        })
        .collect();
    // Primary sort: confidence descending. Secondary: hint id
    // ascending — without the secondary key, equal-confidence hints
    // (e.g. nestjs vs express both at 0.30 before the multi-package
    // NestJS evidence pass) come out in HashMap iteration order,
    // which Rust randomizes per-run. That flipped the human-output
    // framework hint across consecutive scans of the same project.
    out.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}
