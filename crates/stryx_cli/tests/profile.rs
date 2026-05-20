//! End-to-end tests for the cheap-pass profile detector. Each
//! fixture is a synthetic mini-project tree under
//! `tests/fixtures/project-profile/<stack>/`.

use std::path::PathBuf;
use stryx_index::profile::{
    self, AuthHint, DataLayerHint, DeploymentHint, FrameworkHint, LanguageHint, LlmSdkHint,
    ProjectProfile, RuntimeHint, ValidatorHint,
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/project-profile")
        .join(name)
        .canonicalize()
        .expect("fixture exists")
}

fn detect(name: &str) -> ProjectProfile {
    profile::detect(&fixture(name))
}

fn assert_contains<T: PartialEq + std::fmt::Debug>(
    hints: &[profile::Detected<T>],
    expected: T,
    min_confidence: f32,
) {
    let found = hints
        .iter()
        .find(|d| d.id == expected)
        .unwrap_or_else(|| panic!("expected hint {expected:?} not in {hints:#?}"));
    assert!(
        found.confidence >= min_confidence,
        "{expected:?} confidence {} < {min_confidence}",
        found.confidence
    );
    assert!(
        !found.evidence.is_empty(),
        "{expected:?} detected with empty evidence"
    );
}

#[test]
fn bun_hono_drizzle_zod_fixture() {
    let p = detect("bun-hono-drizzle-zod");
    assert_eq!(p.language, LanguageHint::TypeScript);
    assert_contains(&p.runtimes, RuntimeHint::Bun, 0.60);
    assert_contains(&p.frameworks, FrameworkHint::Hono, 0.30);
    assert_contains(&p.data_layers, DataLayerHint::Drizzle, 0.30);
    assert_contains(&p.validators, ValidatorHint::Zod, 0.30);
    assert_contains(&p.auth_layers, AuthHint::BetterAuth, 0.30);
    assert_contains(&p.llm_sdks, LlmSdkHint::OpenAi, 0.30);
    // bun.lock + bunfig.toml + packageManager + dev script — confidence
    // for Bun should clamp at 1.0.
    let bun = p
        .runtimes
        .iter()
        .find(|d| d.id == RuntimeHint::Bun)
        .unwrap();
    assert!(bun.confidence >= 0.95, "Bun confidence: {}", bun.confidence);
    // Node-style lockfiles absent → Node should not appear from
    // lockfile evidence alone in this fixture.
    assert!(
        !p.runtimes.iter().any(|d| d.id == RuntimeHint::Node),
        "Node should not be detected without a Node lockfile/engines"
    );
    // Top-confidence runtime is sorted first.
    assert_eq!(p.runtimes.first().map(|d| d.id), Some(RuntimeHint::Bun));
}

#[test]
fn next_prisma_zod_fixture() {
    let p = detect("next-prisma-zod");
    assert_eq!(p.language, LanguageHint::TypeScript);
    assert_contains(&p.runtimes, RuntimeHint::Node, 0.30);
    assert_contains(&p.frameworks, FrameworkHint::NextBackend, 0.30);
    assert_contains(&p.data_layers, DataLayerHint::Prisma, 0.30);
    assert_contains(&p.validators, ValidatorHint::Zod, 0.30);
    assert_contains(&p.auth_layers, AuthHint::AuthJs, 0.30);
    assert_contains(&p.deployments, DeploymentHint::Vercel, 0.30);
    assert!(
        !p.runtimes.iter().any(|d| d.id == RuntimeHint::Bun),
        "Bun should not be detected without bun-specific evidence"
    );
}

#[test]
fn express_pg_joi_fixture() {
    let p = detect("express-pg-joi");
    assert_eq!(p.language, LanguageHint::TypeScript);
    assert_contains(&p.runtimes, RuntimeHint::Node, 0.30);
    assert_contains(&p.frameworks, FrameworkHint::Express, 0.30);
    assert_contains(&p.data_layers, DataLayerHint::Pg, 0.30);
    assert_contains(&p.validators, ValidatorHint::Joi, 0.30);
    assert!(p.auth_layers.is_empty(), "no auth dep in this fixture");
    assert!(p.llm_sdks.is_empty(), "no LLM dep in this fixture");
}

#[test]
fn empty_fixture_returns_empty_profile() {
    let p = detect("empty");
    assert!(
        p.is_empty(),
        "empty package.json should yield is_empty(): {p:#?}"
    );
    assert_eq!(p, ProjectProfile::default());
}

#[test]
fn missing_root_does_not_panic() {
    let p = profile::detect(&PathBuf::from(
        "/path/that/definitely/does/not/exist/anywhere",
    ));
    assert!(p.is_empty());
}
