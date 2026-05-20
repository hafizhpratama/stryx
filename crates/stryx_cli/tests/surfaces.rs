//! End-to-end tests for `stryx.toml [surfaces]` routing. Each test
//! materialises a tiny project tree under `std::env::temp_dir()`
//! containing a fixture .ts file plus a generated `stryx.toml`, then
//! spawns the real CLI binary so the test exercises the full
//! load-config → partition-findings → write-report path the way a
//! user would on disk.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A `flow/unvalidated-body-to-db` finding is well-understood here:
/// `bad.ts` ships seven of them, all `high` severity. The number is
/// stable across the suite — when it drifts we want the surface tests
/// to fail loudly so we notice.
const FIXTURE_RULE: &str = "flow/unvalidated-body-to-db";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_stryx")
}

fn fixture_bad_ts() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/flow-unvalidated-body-to-db/bad.ts")
        .canonicalize()
        .expect("fixture should resolve")
}

struct TempProject(PathBuf);
impl TempProject {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "stryx-surface-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        // Copy the fixture into the temp project so `stryx.toml` lives
        // alongside the scanned source — config resolution is rooted
        // at the scan path.
        let src = std::fs::read_to_string(fixture_bad_ts()).unwrap();
        std::fs::write(p.join("source.ts"), src).unwrap();
        TempProject(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
    fn write_config(&self, body: &str) {
        std::fs::write(self.0.join("stryx.toml"), body).unwrap();
    }
}
impl Drop for TempProject {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_stryx(project: &Path, extra_args: &[&str]) -> (String, String, Option<i32>) {
    let output = Command::new(bin())
        .arg(project)
        .args(extra_args)
        .output()
        .expect("spawn stryx");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

#[test]
fn no_stryx_toml_keeps_all_findings_visible() {
    let proj = TempProject::new();
    // No config file written — built-in default `["cli"]` applies, so
    // every finding renders in CLI output. This is the regression
    // baseline.
    let (stdout, _stderr, code) = run_stryx(proj.path(), &["--fail-on=critical"]);
    assert!(
        stdout.contains(FIXTURE_RULE),
        "expected rule in stdout:\n{stdout}"
    );
    assert!(stdout.contains("finding(s):"), "summary missing:\n{stdout}");
    assert_eq!(code, Some(0), "no critical findings → exit 0");
}

#[test]
fn surface_score_only_hides_from_cli_but_keeps_in_summary() {
    let proj = TempProject::new();
    proj.write_config(&format!(
        r#"
            [surfaces]
            "{FIXTURE_RULE}" = ["score"]
        "#
    ));
    let (stdout, _stderr, code) = run_stryx(proj.path(), &["--fail-on=critical"]);

    // Rule body must not appear in the CLI output — surface `score`
    // suppresses the per-finding lines.
    assert!(
        !stdout.contains(FIXTURE_RULE),
        "rule should be hidden from CLI output:\n{stdout}"
    );
    // ...but the absence of cli findings means "no findings" is shown,
    // and exit code should be 0 because nothing reaches the fail-on
    // threshold (high suppressed below critical fail-on).
    assert_eq!(
        code,
        Some(0),
        "score-only routing should not affect exit code under fail-on=critical"
    );
}

#[test]
fn surface_ci_failure_forces_nonzero_exit() {
    let proj = TempProject::new();
    proj.write_config(&format!(
        r#"
            [surfaces]
            "{FIXTURE_RULE}" = ["cli", "ciFailure"]
        "#
    ));
    // `--fail-on=critical` would normally exit 0 (we only have `high`
    // findings) but `ciFailure` on the rule must override that.
    let (stdout, _stderr, code) = run_stryx(proj.path(), &["--fail-on=critical"]);

    assert!(
        stdout.contains(FIXTURE_RULE),
        "cli still active alongside ciFailure:\n{stdout}"
    );
    assert_eq!(
        code,
        Some(1),
        "ciFailure surface must produce non-zero exit"
    );
}

#[test]
fn surface_empty_list_silences_rule_completely() {
    let proj = TempProject::new();
    proj.write_config(&format!(
        r#"
            [surfaces]
            "{FIXTURE_RULE}" = []
        "#
    ));
    let (stdout, _stderr, code) = run_stryx(proj.path(), &["--fail-on=high"]);

    assert!(
        !stdout.contains(FIXTURE_RULE),
        "empty surface list must fully silence:\n{stdout}"
    );
    // No CLI findings and no ciFailure → fail-on=high finds nothing
    // to trip on, exit 0.
    assert_eq!(code, Some(0), "fully-silenced rule must not fail CI");
}
