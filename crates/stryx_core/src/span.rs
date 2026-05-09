use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Byte offset into a UTF-8 source file.
pub type ByteOffset = u32;

/// A region of source code: file plus a byte range. Line/column resolution
/// is the reporter's job, not the engine's.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    pub file: PathBuf,
    pub start: ByteOffset,
    pub end: ByteOffset,
}

impl Span {
    pub fn new(file: impl Into<PathBuf>, start: ByteOffset, end: ByteOffset) -> Self {
        Self {
            file: file.into(),
            start,
            end,
        }
    }

    pub fn len(&self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}
