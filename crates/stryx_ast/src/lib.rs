//! Stryx AST layer. Owns the parser entry point and converts oxc spans to
//! the stryx-native [`Span`](stryx_core::Span). Higher layers should depend
//! on this crate, not on `oxc_*` directly — see AGENTS.md.

use std::path::{Path, PathBuf};

pub use oxc_allocator::Allocator;
pub use oxc_ast::ast;
pub use oxc_ast_visit::{Visit, walk};
pub use oxc_parser::Parser;
pub use oxc_semantic::{Semantic, SemanticBuilder};
pub use oxc_span::{SourceType, Span as OxcSpan};
pub use oxc_syntax::scope::ScopeFlags;

use stryx_core::{Span, StryxError};

/// A parsed TypeScript/JavaScript source file. The `Allocator` and the
/// borrowed source string both live as long as this struct, which keeps
/// the AST referenced by `program` valid.
pub struct ParsedFile<'a> {
    pub path: PathBuf,
    pub source: &'a str,
    pub source_type: SourceType,
    pub program: oxc_ast::ast::Program<'a>,
}

/// Parse a TypeScript/JavaScript source. The caller owns the [`Allocator`]
/// and source string; the returned [`ParsedFile`] borrows from both.
pub fn parse<'a>(
    allocator: &'a Allocator,
    path: &Path,
    source: &'a str,
) -> Result<ParsedFile<'a>, StryxError> {
    let source_type = SourceType::from_path(path).unwrap_or_else(|_| SourceType::tsx());
    let ret = Parser::new(allocator, source, source_type).parse();

    if !ret.errors.is_empty() {
        let message = ret
            .errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(StryxError::Parse {
            path: path.display().to_string(),
            message,
        });
    }

    Ok(ParsedFile {
        path: path.to_path_buf(),
        source,
        source_type,
        program: ret.program,
    })
}

/// Convert an oxc span (file-relative byte range) into a [`Span`] anchored
/// to a specific file.
pub fn to_span(file: &Path, span: OxcSpan) -> Span {
    Span::new(file.to_path_buf(), span.start, span.end)
}
