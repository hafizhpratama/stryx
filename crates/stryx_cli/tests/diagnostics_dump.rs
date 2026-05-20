//! Smoke test for the `STRYX_DEBUG_DUMP=1` diagnostic side-channel.
//!
//! Spawning the compiled binary (rather than mutating the parent
//! process env) keeps us off Rust 2024's `set_var` unsafe path and
//! mirrors how a developer would actually flip this flag in the wild.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn debug_dump_writes_report_to_tmp() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/flow-unvalidated-body-to-db/bad.ts")
        .canonicalize()
        .expect("fixture should resolve");

    let output = Command::new(env!("CARGO_BIN_EXE_stryx"))
        .arg(&fixture)
        .arg("--format=human")
        // exit 0 even when findings present, so cargo test sees Ok
        .arg("--fail-on=critical")
        .env("STRYX_DEBUG_DUMP", "1")
        .output()
        .expect("spawn stryx binary");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Locate the "wrote diagnostics to <path>" announcement on stderr.
    let dump_line = stderr
        .lines()
        .find(|l| l.contains("wrote diagnostics to "))
        .unwrap_or_else(|| {
            panic!(
                "stderr missing 'wrote diagnostics' line.\nstderr:\n{stderr}\nstdout:\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        });

    let dump_path = dump_line
        .split("wrote diagnostics to ")
        .nth(1)
        .expect("path follows marker")
        .trim();

    assert!(
        dump_path.starts_with("/tmp/stryx-report-") && dump_path.ends_with(".json"),
        "unexpected dump path: {dump_path}"
    );

    let raw =
        std::fs::read_to_string(dump_path).unwrap_or_else(|e| panic!("read dump {dump_path}: {e}"));
    let parsed: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("dump is not valid JSON: {e}"));

    let findings = parsed
        .get("findings")
        .and_then(|v| v.as_array())
        .expect("dump has a `findings` array");
    assert!(
        !findings.is_empty(),
        "expected at least one finding for the unvalidated-body-to-db fixture, got: {parsed}"
    );

    // Best-effort cleanup; ignore failure (test still passed by here).
    let _ = std::fs::remove_file(dump_path);
}
