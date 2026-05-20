//! `runtime/node` adapter — Node.js standard-library sinks.
//!
//! Node.js is the default TypeScript backend runtime. Two of its
//! standard-library namespaces drive multiple flow rules:
//!
//! - `child_process` — the shell/process exec surface that
//!   [`crate::flows::command_injection_via_exec`] inspects for
//!   CWE-78 / OWASP A03 command-injection sinks.
//! - `fs` (and `fs.promises`) — the filesystem surface that
//!   [`crate::flows::path_traversal`] inspects for CWE-22 / CWE-23
//!   path-traversal sinks.
//!
//! These sinks were previously recognised inline by per-rule
//! predicates ([`crate::steps::sinks::exec::is_exec_sink_call`],
//! [`crate::steps::sinks::fs::is_fs_sink_call`]). This adapter
//! mirrors those predicates as substrate-style [`SinkPattern`]
//! entries so that once rules consume `ctx.match_sink` they can
//! attribute findings to `runtime/node/<op>` instead of an opaque
//! inline match.
//!
//! ## child_process sinks (Critical floor)
//!
//! Six recognised methods, each contributed as a separate
//! [`SinkPattern`] for one-finding-per-pattern attribution:
//!
//! - `exec` / `execSync` — invoke a shell; first arg is a string
//!   the shell parses verbatim. Body taint here is arbitrary code
//!   execution.
//! - `execFile` / `execFileSync` — invoke a binary by path; first
//!   arg is the binary path. Body taint here is binary-path control.
//! - `spawn` / `spawnSync` — same shape as `execFile`, streaming I/O.
//!
//! For each method we contribute **three** matchers in the pattern:
//!
//! - `ImportedCall { module: "child_process", name: <method> }` —
//!   the canonical destructured-import shape
//!   (`import { exec } from "child_process"; exec("ls")`).
//! - `ImportedCall { module: "node:child_process", name: <method> }`
//!   — Node's `node:` scheme is equivalent to the bare specifier
//!   (per Node docs); both must activate the sink.
//! - `MethodCall { receiver: "child_process", method: <method> }` —
//!   the namespace-import shape
//!   (`import * as child_process from "child_process"; child_process.exec(...)`)
//!   or the require-with-original-name shape
//!   (`const child_process = require("child_process")`).
//!
//! Project-local aliases (`cp.exec`, `childProcess.exec`) that the
//! inline recogniser accepts via a hardcoded receiver list are
//! intentionally **not** mirrored here — those are stylistic
//! renamings, not part of the Node runtime contract. The inline
//! predicate continues to cover them during the rule-migration
//! slice; once rules consume the registry, alias support would
//! move into a separate "common renamings" concern rather than
//! into the Node-stdlib adapter.
//!
//! Severity floor is `Critical` on every exec sink — CWE-78 is
//! consistently a Critical finding regardless of which child_process
//! variant introduced the splice.
//!
//! ## fs sinks (High floor)
//!
//! Ten recognised operations, covering the read / write / append /
//! delete / stat / stream surface that the inline recogniser in
//! [`crate::steps::sinks::fs`] already recognises. Per pattern, we
//! contribute **two** matchers:
//!
//! - `MethodCall { receiver: "fs", method: <op> }` — the standard
//!   CommonJS shape (`fs.readFile(path, ...)`).
//! - `MethodCall { receiver: "fs.promises", method: <op> }` — the
//!   namespaced promise interface (`fs.promises.readFile(path)`).
//!
//! The bare-alias receiver `fsPromises` (which the inline
//! recogniser accepts) is a destructured-binding rename and stays
//! with the inline predicate, for the same reason as `cp`/`childProcess`
//! above. The bare-import shape
//! (`import { readFile } from "fs"; readFile(...)`) is similarly
//! out of scope here — the inline recogniser also declines it
//! (see the module comment on [`crate::steps::sinks::fs`]) because
//! the method names are common enough that bare matching needs
//! scope-aware import tracking to avoid false positives.
//!
//! Severity floor is `High` — path-traversal can leak `/etc/passwd`,
//! `.env`, or application source, or overwrite trusted files;
//! CWE-22 / CWE-23 are consistently High.
//!
//! ## Sources / sanitisers / guards
//!
//! None. The Node runtime is a sink contributor only — it does not
//! introduce taint (request input is contributed by framework
//! adapters), nor does it sanitise (validation adapters own that
//! role).
//!
//! ## Activation
//!
//! Default `is_enabled` — active when the project profile contains a
//! `RuntimeHint::Node` entry at confidence ≥
//! [`ENABLE_CONFIDENCE_FLOOR`] (`0.60`). The profile crate
//! serialises `Node` as `"node"`, which matches the `node` suffix in
//! this adapter's `runtime/node` ID.
//!
//! [ADR 0014][adr] notes that a future iteration may switch
//! `runtime/node` to always-active (most TypeScript backend projects
//! imply Node even without an explicit detection signal), but the
//! initial slice uses the default profile-gated path so a Bun-only
//! or Deno-only project doesn't see spurious `runtime/node` sink
//! attribution.
//!
//! [`ENABLE_CONFIDENCE_FLOOR`]: crate::adapters::ENABLE_CONFIDENCE_FLOOR
//! [adr]: ../../../docs/decisions/0014-adapter-substrate-api.md

use crate::adapters::{AdapterId, AdapterKind, AstMatcher, SinkKind, SinkPattern, StackAdapter};
use stryx_core::Severity;

pub struct NodeAdapter;

// =============================================================================
// child_process sinks — Exec / Critical
// =============================================================================
//
// Each pattern carries three matchers: two `ImportedCall` variants
// (covering the bare and `node:`-scheme specifier) and one `MethodCall`
// variant (covering namespace-import / require-with-original-name).
// The matcher set is intentionally identical across every method so
// adding a new child_process op is a copy-paste of the three-matcher
// block with a different method name.

static SINKS_EXEC: &[SinkPattern] = &[
    SinkPattern {
        id: "runtime/node/exec",
        sink: SinkKind::Exec,
        matchers: &[
            AstMatcher::ImportedCall {
                module: "child_process",
                name: "exec",
            },
            AstMatcher::ImportedCall {
                module: "node:child_process",
                name: "exec",
            },
            AstMatcher::MethodCall {
                receiver: "child_process",
                method: "exec",
            },
        ],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "runtime/node/exec-sync",
        sink: SinkKind::Exec,
        matchers: &[
            AstMatcher::ImportedCall {
                module: "child_process",
                name: "execSync",
            },
            AstMatcher::ImportedCall {
                module: "node:child_process",
                name: "execSync",
            },
            AstMatcher::MethodCall {
                receiver: "child_process",
                method: "execSync",
            },
        ],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "runtime/node/exec-file",
        sink: SinkKind::Exec,
        matchers: &[
            AstMatcher::ImportedCall {
                module: "child_process",
                name: "execFile",
            },
            AstMatcher::ImportedCall {
                module: "node:child_process",
                name: "execFile",
            },
            AstMatcher::MethodCall {
                receiver: "child_process",
                method: "execFile",
            },
        ],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "runtime/node/exec-file-sync",
        sink: SinkKind::Exec,
        matchers: &[
            AstMatcher::ImportedCall {
                module: "child_process",
                name: "execFileSync",
            },
            AstMatcher::ImportedCall {
                module: "node:child_process",
                name: "execFileSync",
            },
            AstMatcher::MethodCall {
                receiver: "child_process",
                method: "execFileSync",
            },
        ],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "runtime/node/spawn",
        sink: SinkKind::Exec,
        matchers: &[
            AstMatcher::ImportedCall {
                module: "child_process",
                name: "spawn",
            },
            AstMatcher::ImportedCall {
                module: "node:child_process",
                name: "spawn",
            },
            AstMatcher::MethodCall {
                receiver: "child_process",
                method: "spawn",
            },
        ],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "runtime/node/spawn-sync",
        sink: SinkKind::Exec,
        matchers: &[
            AstMatcher::ImportedCall {
                module: "child_process",
                name: "spawnSync",
            },
            AstMatcher::ImportedCall {
                module: "node:child_process",
                name: "spawnSync",
            },
            AstMatcher::MethodCall {
                receiver: "child_process",
                method: "spawnSync",
            },
        ],
        severity_floor: Severity::Critical,
    },
];

// =============================================================================
// fs sinks — Filesystem / High
// =============================================================================
//
// Scope chosen to overlap with the inline recogniser in
// `crate::steps::sinks::fs`: ten high-signal read / write / append /
// delete / stat / stream operations. Each pattern carries two
// matchers — the standard `fs.<op>` shape and the
// `fs.promises.<op>` shape — so projects mixing the sync and
// promise styles get a single attribution per op.

static SINKS_FS: &[SinkPattern] = &[
    // ── Read ─────────────────────────────────────────────────────────
    SinkPattern {
        id: "runtime/node/fs-read-file",
        sink: SinkKind::Filesystem,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "fs",
                method: "readFile",
            },
            AstMatcher::MethodCall {
                receiver: "fs.promises",
                method: "readFile",
            },
        ],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "runtime/node/fs-read-file-sync",
        sink: SinkKind::Filesystem,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "fs",
                method: "readFileSync",
            },
            AstMatcher::MethodCall {
                receiver: "fs.promises",
                method: "readFileSync",
            },
        ],
        severity_floor: Severity::High,
    },
    // ── Write ────────────────────────────────────────────────────────
    SinkPattern {
        id: "runtime/node/fs-write-file",
        sink: SinkKind::Filesystem,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "fs",
                method: "writeFile",
            },
            AstMatcher::MethodCall {
                receiver: "fs.promises",
                method: "writeFile",
            },
        ],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "runtime/node/fs-write-file-sync",
        sink: SinkKind::Filesystem,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "fs",
                method: "writeFileSync",
            },
            AstMatcher::MethodCall {
                receiver: "fs.promises",
                method: "writeFileSync",
            },
        ],
        severity_floor: Severity::High,
    },
    // ── Append ───────────────────────────────────────────────────────
    SinkPattern {
        id: "runtime/node/fs-append-file",
        sink: SinkKind::Filesystem,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "fs",
                method: "appendFile",
            },
            AstMatcher::MethodCall {
                receiver: "fs.promises",
                method: "appendFile",
            },
        ],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "runtime/node/fs-append-file-sync",
        sink: SinkKind::Filesystem,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "fs",
                method: "appendFileSync",
            },
            AstMatcher::MethodCall {
                receiver: "fs.promises",
                method: "appendFileSync",
            },
        ],
        severity_floor: Severity::High,
    },
    // ── Delete ───────────────────────────────────────────────────────
    SinkPattern {
        id: "runtime/node/fs-unlink",
        sink: SinkKind::Filesystem,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "fs",
                method: "unlink",
            },
            AstMatcher::MethodCall {
                receiver: "fs.promises",
                method: "unlink",
            },
        ],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "runtime/node/fs-unlink-sync",
        sink: SinkKind::Filesystem,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "fs",
                method: "unlinkSync",
            },
            AstMatcher::MethodCall {
                receiver: "fs.promises",
                method: "unlinkSync",
            },
        ],
        severity_floor: Severity::High,
    },
    // ── Streams ──────────────────────────────────────────────────────
    SinkPattern {
        id: "runtime/node/fs-create-read-stream",
        sink: SinkKind::Filesystem,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "fs",
                method: "createReadStream",
            },
            AstMatcher::MethodCall {
                receiver: "fs.promises",
                method: "createReadStream",
            },
        ],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "runtime/node/fs-create-write-stream",
        sink: SinkKind::Filesystem,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "fs",
                method: "createWriteStream",
            },
            AstMatcher::MethodCall {
                receiver: "fs.promises",
                method: "createWriteStream",
            },
        ],
        severity_floor: Severity::High,
    },
];

// =============================================================================
// Flat list — what the adapter exposes
// =============================================================================
//
// `STATIC_SINKS` is the concrete `&'static [SinkPattern]` the trait
// method returns. Building it at module-init time as a
// `Vec`-via-`OnceLock` would defeat the substrate's "no per-scan
// allocation" rule, so the two source slices above are sized
// individually and a third slice concatenates them via a fixed-size
// const array. Adding a new sink means bumping the matching count
// in the test below; no other coordination needed.

static SINKS: [SinkPattern; SINKS_EXEC.len() + SINKS_FS.len()] = {
    let mut out = [SINKS_EXEC[0]; SINKS_EXEC.len() + SINKS_FS.len()];
    let mut i = 0;
    while i < SINKS_EXEC.len() {
        out[i] = SINKS_EXEC[i];
        i += 1;
    }
    let mut j = 0;
    while j < SINKS_FS.len() {
        out[SINKS_EXEC.len() + j] = SINKS_FS[j];
        j += 1;
    }
    out
};

impl StackAdapter for NodeAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("runtime/node")
    }
    fn kind(&self) -> AdapterKind {
        AdapterKind::Runtime
    }
    fn sinks(&self) -> &'static [SinkPattern] {
        &SINKS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stryx_index::profile::{Detected, ProjectProfile, RuntimeHint};

    #[test]
    fn node_adapter_exposes_expected_sink_patterns() {
        // Six child_process sinks + ten fs sinks = sixteen total.
        // This pin updates whenever the recognised Node-stdlib
        // surface grows. The included key IDs cover at least one
        // representative from each sub-family (exec, exec-file,
        // spawn, fs read, fs write, fs stream) so a typo in any
        // sub-family is caught here rather than in a downstream
        // rule's silent miss.
        let sinks = NodeAdapter.sinks();
        assert_eq!(sinks.len(), 16);
        let ids: Vec<&str> = sinks.iter().map(|s| s.id).collect();

        // child_process — all six variants present.
        assert!(ids.contains(&"runtime/node/exec"));
        assert!(ids.contains(&"runtime/node/exec-sync"));
        assert!(ids.contains(&"runtime/node/exec-file"));
        assert!(ids.contains(&"runtime/node/exec-file-sync"));
        assert!(ids.contains(&"runtime/node/spawn"));
        assert!(ids.contains(&"runtime/node/spawn-sync"));

        // fs — representative ops across read / write / delete /
        // stream, plus the sync split so a regression that drops
        // either side surfaces.
        assert!(ids.contains(&"runtime/node/fs-read-file"));
        assert!(ids.contains(&"runtime/node/fs-read-file-sync"));
        assert!(ids.contains(&"runtime/node/fs-write-file"));
        assert!(ids.contains(&"runtime/node/fs-write-file-sync"));
        assert!(ids.contains(&"runtime/node/fs-append-file"));
        assert!(ids.contains(&"runtime/node/fs-append-file-sync"));
        assert!(ids.contains(&"runtime/node/fs-unlink"));
        assert!(ids.contains(&"runtime/node/fs-unlink-sync"));
        assert!(ids.contains(&"runtime/node/fs-create-read-stream"));
        assert!(ids.contains(&"runtime/node/fs-create-write-stream"));
    }

    #[test]
    fn node_adapter_is_runtime_kind() {
        assert_eq!(NodeAdapter.kind(), AdapterKind::Runtime);
        assert_eq!(NodeAdapter.id(), AdapterId("runtime/node"));
    }

    #[test]
    fn node_exec_sinks_floor_at_critical() {
        // Every `SinkKind::Exec` sink the adapter contributes must
        // carry a `Severity::Critical` floor — command injection is
        // a CWE-78 / OWASP A03 surface and the floor is what stops
        // a downstream rule from quietly downgrading a child_process
        // splice to anything less than Critical.
        for sink in NodeAdapter.sinks() {
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
    fn node_fs_sinks_floor_at_high() {
        // Every `SinkKind::Filesystem` sink the adapter contributes
        // must carry a `Severity::High` floor — CWE-22 / CWE-23 path
        // traversal is a High-severity surface (file disclosure /
        // overwrite, not direct code execution).
        for sink in NodeAdapter.sinks() {
            if matches!(sink.sink, SinkKind::Filesystem) {
                assert_eq!(
                    sink.severity_floor,
                    Severity::High,
                    "fs sink {} should floor at High",
                    sink.id
                );
            }
        }
    }

    #[test]
    fn is_enabled_returns_true_under_node_profile() {
        // High-confidence Node detection in the profile must activate
        // the adapter via the default `is_enabled` path — the
        // `runtime/<name>` adapter ID suffix `node` matches the serde
        // spelling of `RuntimeHint::Node` (kebab-case → `"node"`).
        let profile = ProjectProfile {
            runtimes: vec![Detected {
                id: RuntimeHint::Node,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(NodeAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_bun_profile() {
        // A Bun-only profile must not activate the Node adapter, even
        // at high confidence — adapter activation is per-name, not
        // per-kind. This is the guard that keeps Node-stdlib sink
        // attribution out of pure-Bun projects (which use `Bun.spawn`
        // / `Bun.file` and are covered by a future `runtime/bun`
        // adapter instead).
        let profile = ProjectProfile {
            runtimes: vec![Detected {
                id: RuntimeHint::Bun,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!NodeAdapter.is_enabled(&profile));
    }
}
