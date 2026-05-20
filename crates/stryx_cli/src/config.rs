//! `stryx.toml` configuration. Loaded from the scan root if present;
//! a missing file is not an error, it just means defaults apply.
//!
//! Today this module owns the `[surfaces]` section — per-rule routing
//! of findings to different output channels (cli output, PR comment,
//! score-only, CI failure). Other config sections documented in
//! `docs/getting-started.md` (`[scan]`, `[severity]`, `[rules]`,
//! `[llm]`, `[output]`) are not yet wired up here; they are part of
//! the v0.5.0+ roadmap and would land as additive fields on
//! [`StryxConfig`].
//!
//! The parsing surface is intentionally tolerant: unknown top-level
//! tables and unknown keys are ignored rather than rejected, so a
//! `stryx.toml` written against a newer CLI version still loads on
//! an older binary (it just stops applying the newer settings).

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

/// A finding's downstream destination. A rule can be routed to zero
/// or more surfaces; an empty list silences the rule entirely (the
/// finding still exists for the engine but is never reported anywhere).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Surface {
    /// Print in the human/JSON report — the default for every rule
    /// unless overridden.
    Cli,
    /// Include in the PR-comment markdown produced by the GitHub
    /// Action. Recorded as metadata today (the PR-comment writer
    /// itself is a v0.6.0 roadmap item).
    PrComment,
    /// Count toward the summary + score but suppress from CLI
    /// output. Useful for surfacing trends in dashboards without
    /// drowning the contributor in inline noise.
    Score,
    /// Trigger a non-zero exit regardless of `--fail-on`. Useful
    /// for hard CI gates (e.g. a `flow/sql-injection` finding must
    /// always block merge even if `--fail-on=high` is configured to
    /// allow some categories through).
    CiFailure,
}

/// Top-level config. Additive — new sections can be added without
/// breaking existing `stryx.toml` files in the wild.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct StryxConfig {
    /// `[surfaces]` table — maps rule id (or the literal key
    /// `"default"`) to a list of [`Surface`]s. The `default` key
    /// applies to any rule not explicitly listed; in its absence,
    /// the built-in default `["cli"]` applies.
    #[serde(default)]
    pub surfaces: HashMap<String, Vec<Surface>>,
}

impl StryxConfig {
    /// Read `stryx.toml` from `scan_root` (or its parent if
    /// `scan_root` is a file). Returns the default config when no
    /// file exists. A malformed file logs at `warn` and falls back
    /// to defaults rather than failing the scan — the analysis
    /// itself is more important than a perfect config parse, and
    /// the user already sees the warning in the log.
    pub fn load(scan_root: &Path) -> Self {
        let root = if scan_root.is_dir() {
            scan_root
        } else {
            scan_root.parent().unwrap_or(Path::new("."))
        };
        let path = root.join("stryx.toml");
        if !path.exists() {
            return Self::default();
        }
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!(?path, %err, "stryx.toml read failed; using defaults");
                return Self::default();
            }
        };
        match toml::from_str::<Self>(&raw) {
            Ok(cfg) => cfg,
            Err(err) => {
                tracing::warn!(?path, %err, "stryx.toml parse failed; using defaults");
                Self::default()
            }
        }
    }

    /// Return the surface list applied to `rule_id`. Priority:
    /// explicit per-rule entry, then the `"default"` entry, then the
    /// built-in `["cli"]`. The built-in default lives here (not in
    /// the `Default` impl) so the absence of any `[surfaces]` table
    /// means "render everything to the CLI", not "silence
    /// everything."
    pub fn surfaces_for(&self, rule_id: &str) -> &[Surface] {
        if let Some(explicit) = self.surfaces.get(rule_id) {
            return explicit;
        }
        if let Some(default) = self.surfaces.get("default") {
            return default;
        }
        &[Surface::Cli]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_stryx_toml_yields_default_config() {
        let dir = tempdir();
        let cfg = StryxConfig::load(dir.path());
        // No surfaces table → every rule routes to `["cli"]` via the
        // built-in fallback.
        assert_eq!(cfg.surfaces_for("flow/x"), &[Surface::Cli]);
    }

    #[test]
    fn explicit_rule_override_wins_over_default() {
        let dir = tempdir();
        std::fs::write(
            dir.path().join("stryx.toml"),
            r#"
                [surfaces]
                default = ["cli"]
                "flow/x" = ["score"]
            "#,
        )
        .unwrap();
        let cfg = StryxConfig::load(dir.path());
        assert_eq!(cfg.surfaces_for("flow/x"), &[Surface::Score]);
        assert_eq!(cfg.surfaces_for("flow/other"), &[Surface::Cli]);
    }

    #[test]
    fn default_key_replaces_builtin_default() {
        let dir = tempdir();
        std::fs::write(
            dir.path().join("stryx.toml"),
            r#"
                [surfaces]
                default = ["score", "ciFailure"]
            "#,
        )
        .unwrap();
        let cfg = StryxConfig::load(dir.path());
        assert_eq!(
            cfg.surfaces_for("flow/x"),
            &[Surface::Score, Surface::CiFailure]
        );
    }

    #[test]
    fn empty_surfaces_list_silences_rule_completely() {
        let dir = tempdir();
        std::fs::write(
            dir.path().join("stryx.toml"),
            r#"
                [surfaces]
                "flow/x" = []
            "#,
        )
        .unwrap();
        let cfg = StryxConfig::load(dir.path());
        assert!(cfg.surfaces_for("flow/x").is_empty());
    }

    #[test]
    fn malformed_toml_falls_back_to_default() {
        let dir = tempdir();
        std::fs::write(dir.path().join("stryx.toml"), "this is = not [ toml").unwrap();
        let cfg = StryxConfig::load(dir.path());
        assert_eq!(cfg.surfaces_for("flow/x"), &[Surface::Cli]);
    }

    /// Tiny temp-dir helper. The full `tempfile` crate is overkill
    /// for two tests; this gives an auto-removed scratch directory
    /// in `std::env::temp_dir()`.
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "stryx-cfg-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
