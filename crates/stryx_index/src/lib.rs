//! Project-level semantic index. Stub for v0.0.1: types are defined so the
//! Rule trait can reference them, but the extract/merge phases described in
//! `docs/architecture/semantic-index.md` are not yet implemented.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Hint about the framework a file participates in. Rules use this to
/// decide whether to engage at all (e.g. Next.js rules skip non-Next files).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FrameworkHint {
    Generic,
    NextJs,
    Hono,
    Express,
    NestJs,
}

/// Per-file index entry. The full schema is described in
/// `docs/architecture/semantic-index.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub framework: FrameworkHint,
}

/// Project-wide index. Empty for v0.0.1; populated once cross-file rules ship.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProjectIndex {
    pub files: Vec<FileEntry>,
}

impl ProjectIndex {
    pub fn new() -> Self {
        Self::default()
    }
}
