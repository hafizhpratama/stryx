//! `runtime/bun` adapter — Bun-runtime global sinks.
//!
//! Bun is a TypeScript-first JavaScript runtime that exposes a small
//! set of dangerous primitives directly off the global `Bun` namespace:
//! `Bun.spawn` / `Bun.spawnSync` shell out to the OS, and `Bun.file` /
//! `Bun.write` are the runtime's filesystem entry points. These shapes
//! are unique to Bun (no Node analogue at the same call site), so they
//! belong in a runtime adapter rather than a framework one — they fire
//! regardless of whether the project uses Hono, Elysia, or a bare
//! `Bun.serve` handler.
//!
//! ## Sinks
//!
//! Process / shell execution (`SinkKind::Exec`, `Severity::Critical`
//! floor) — `Bun.spawn` and `Bun.spawnSync` accept either an `argv`
//! array (safe-ish — the first element is the program, no shell parses
//! the rest) or, in practice, a tainted string mixed into the array.
//! Both shapes reach `flow/command-injection-via-exec`. The floor is
//! `Critical` because successful command injection is RCE-class
//! (OWASP A03:2021 / CWE-78), matching the floor that the existing
//! inline recogniser in [`crate::steps::sinks::exec`] already assigns
//! for `child_process::exec` and `Bun.spawn` calls.
//!
//! Filesystem operations (`SinkKind::Filesystem`, `Severity::High`
//! floor) — `Bun.file(path)` opens a `BunFile` handle and `Bun.write`
//! writes bytes to a path-or-handle target. Tainted path arguments
//! reach `flow/path-traversal` (CWE-22). The floor is `High`: the
//! exposure here is read/write outside the intended directory, which
//! is severe but typically narrower than full RCE — and consistent with
//! how the inline path-traversal recogniser scores `fs.readFile` /
//! `fs.writeFile` for the same shape.
//!
//! ## Sources
//!
//! None. Bun's request handler signature inside `Bun.serve({ fetch })`
//! is the Web Fetch `Request` shape — `req.json()`, `req.text()`,
//! `req.formData()`. Those calls are already recognised generically by
//! [`crate::steps::sources::body`] across `req` / `request` / `c` /
//! `ctx` receivers, which spans Bun-on-Hono, Bun-on-Elysia, and bare
//! `Bun.serve`. Attributing them to this adapter would double-count
//! when the framework adapter is also active. The generic recogniser
//! stays the source of truth.
//!
//! ## Activation
//!
//! Default `is_enabled` — active when the project profile contains a
//! `RuntimeHint::Bun` entry at confidence ≥
//! [`ENABLE_CONFIDENCE_FLOOR`] (`0.60`). The profile crate serialises
//! `Bun` as `"bun"`, which matches the `bun` suffix in this adapter's
//! `runtime/bun` ID.
//!
//! [`ENABLE_CONFIDENCE_FLOOR`]: crate::adapters::ENABLE_CONFIDENCE_FLOOR

use crate::adapters::{AdapterId, AdapterKind, AstMatcher, SinkKind, SinkPattern, StackAdapter};
use stryx_core::Severity;

pub struct BunAdapter;

static SINKS: &[SinkPattern] = &[
    // ── Process / shell execution ────────────────────────────────────
    SinkPattern {
        id: "runtime/bun/spawn",
        sink: SinkKind::Exec,
        matchers: &[AstMatcher::NamespaceCall {
            namespace: "Bun",
            member: "spawn",
        }],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "runtime/bun/spawn-sync",
        sink: SinkKind::Exec,
        matchers: &[AstMatcher::NamespaceCall {
            namespace: "Bun",
            member: "spawnSync",
        }],
        severity_floor: Severity::Critical,
    },
    // ── Filesystem operations ────────────────────────────────────────
    SinkPattern {
        id: "runtime/bun/file",
        sink: SinkKind::Filesystem,
        matchers: &[AstMatcher::NamespaceCall {
            namespace: "Bun",
            member: "file",
        }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "runtime/bun/write",
        sink: SinkKind::Filesystem,
        matchers: &[AstMatcher::NamespaceCall {
            namespace: "Bun",
            member: "write",
        }],
        severity_floor: Severity::High,
    },
];

impl StackAdapter for BunAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("runtime/bun")
    }
    fn kind(&self) -> AdapterKind {
        AdapterKind::Runtime
    }
    fn sinks(&self) -> &'static [SinkPattern] {
        SINKS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stryx_index::profile::{Detected, ProjectProfile, RuntimeHint};

    #[test]
    fn bun_adapter_exposes_expected_sink_patterns() {
        let sinks = BunAdapter.sinks();
        assert_eq!(sinks.len(), 4);
        let ids: Vec<&str> = sinks.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"runtime/bun/spawn"));
        assert!(ids.contains(&"runtime/bun/spawn-sync"));
        assert!(ids.contains(&"runtime/bun/file"));
        assert!(ids.contains(&"runtime/bun/write"));
    }

    #[test]
    fn bun_adapter_is_runtime_kind() {
        assert_eq!(BunAdapter.kind(), AdapterKind::Runtime);
        assert_eq!(BunAdapter.id(), AdapterId("runtime/bun"));
    }

    #[test]
    fn bun_exec_sinks_floor_at_critical() {
        // `Bun.spawn` / `Bun.spawnSync` are RCE-class on tainted input
        // (OWASP A03:2021 / CWE-78). The adapter floor is `Critical`;
        // rules may raise but never lower it.
        for sink in BunAdapter.sinks() {
            if matches!(sink.sink, SinkKind::Exec) {
                assert_eq!(
                    sink.severity_floor,
                    Severity::Critical,
                    "exec sink {} should floor at Critical",
                    sink.id
                );
            }
        }
    }

    #[test]
    fn bun_fs_sinks_floor_at_high() {
        // `Bun.file` / `Bun.write` reach `flow/path-traversal`
        // (CWE-22). The floor is `High` — severe but narrower than
        // full RCE, mirroring the inline `fs.readFile` / `fs.writeFile`
        // recogniser's severity.
        for sink in BunAdapter.sinks() {
            if matches!(sink.sink, SinkKind::Filesystem) {
                assert_eq!(
                    sink.severity_floor,
                    Severity::High,
                    "filesystem sink {} should floor at High",
                    sink.id
                );
            }
        }
    }

    #[test]
    fn is_enabled_returns_true_under_bun_profile() {
        // High-confidence Bun detection in the profile must activate
        // the adapter via the default `is_enabled` path (matches the
        // `runtime/<name>` adapter ID suffix against the
        // `RuntimeHint::Bun` serde spelling `"bun"`).
        let profile = ProjectProfile {
            runtimes: vec![Detected {
                id: RuntimeHint::Bun,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(BunAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_node_profile() {
        // A Node-only profile must not activate the Bun adapter, even
        // at high confidence — adapter activation is per-name, not
        // per-kind.
        let profile = ProjectProfile {
            runtimes: vec![Detected {
                id: RuntimeHint::Node,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!BunAdapter.is_enabled(&profile));
    }
}
