# Semantic Index

The project-level read-only index that powers cross-file analysis.

> Foundational reference. Read [ADR 0003](../decisions/0003-cross-file-and-taint-as-core.md)
> first for *why* a project index exists. Read [`taint-engine.md`](taint-engine.md)
> for the engine that queries it most heavily.

## Implementation status (as of v0.4.x)

This document mixes shipped behaviour with design intent. The
following are **not yet implemented** — flagged inline with 📋:

- `re_export_chain` traversal in `SymbolEntry` — `ProjectIndex::resolve`
  handles direct and wildcard re-exports, but the richer `SymbolEntry`
  design below remains design intent.
- On-disk SQLite cache at `~/.cache/stryx/index/` — not in code.
  v0.4.x rebuilds the index every scan from in-memory parse results.
- Tarjan SCC detection on circular imports — not in code. Cycles
  in the import graph are handled by the resolver returning `None`
  on the second hop, which is conservative but loses precision.

What **is** built: `FileSummary` per file with exports/locals/
imports/classes maps; `ProjectIndex::resolve` and `resolve_summary`
walking the import map for relative specifiers and tsconfig/jsconfig
path aliases; per-file extract populated by flow-rule extract passes;
`classes` field for class-method resolution (NestJS-shaped controllers).
The next planned extension is `ProjectProfile` for stack-aware adapter
enablement; see [project-profile.md](project-profile.md).

## What it is and why it exists

The semantic index is a project-level data structure built once per
scan. It holds enough information to answer cross-file questions
without keeping every file's AST resident:

- **Where is symbol X defined?**
- **Who imports symbol X from which files?**
- **Who calls function Y?**
- **What framework does file Z belong to?**

Without this index, cross-file rules would either re-parse on every
query (slow) or hold every AST in memory (expensive). The index
extracts the small subset of information cross-file analysis actually
needs and frees the parser arenas. ASTs are re-parsed on demand for the
few zones that need full inspection.

The index lives in `crates/stryx_index/`. It is queried by Layer 2
rules through `RuleContext` and by the taint engine through
`TaintContext`.

## Data model

Concrete struct shapes (simplified for clarity):

```rust
pub struct ProjectIndex {
    files: HashMap<FileId, FileEntry>,
    symbols: HashMap<SymbolId, SymbolEntry>,
    imports: HashMap<FileId, Vec<ImportEdge>>,
    callers: HashMap<SymbolId, Vec<CallSite>>,
    framework_hints: HashMap<FileId, FrameworkHint>,
}

pub struct FileEntry {
    path: PathBuf,
    content_hash: Blake3Hash,
    source_type: SourceType,
    size_bytes: u32,
    parser_version: u16,
}

pub struct SymbolEntry {
    name: CompactString,
    file_id: FileId,
    span: Span,
    kind: SymbolKind,         // Function | Const | Class | Type | Enum
    exported: bool,
    // 📋 Phase 3 — barrel-file `export * from "./other"` chains.
    re_export_chain: Option<Vec<SymbolId>>,
}

pub struct ImportEdge {
    from_file: FileId,
    to_file: Option<FileId>,  // None = external (npm) or unresolved
    specifier: CompactString, // "./lib/users", "zod", "@/lib/db"
    imports: Vec<ImportSpec>, // {Foo} | * as Bar | default as Baz
}

pub struct CallSite {
    in_file: FileId,
    in_function: Option<SymbolId>,
    span: Span,
    arg_count: u8,
}

pub enum FrameworkHint {
    Nextjs { app_router: bool, version: Option<SemVer> },
    Hono,
    Express,
    Generic,
}
```

`FileId` and `SymbolId` are interned `u32` handles. They are stable
within a single scan but not across scans (regenerate on each build).

## Construction pipeline

```
[1] Discovery       (ignore-aware traversal)
       │
       ▼
[2] Parallel parse  (rayon, per-file arena)
       │
       ▼
[3] Per-file extract (visitor that emits index entries)
       │
       ▼
[4] Free arena      (per-file arenas dropped after extraction)
       │
       ▼
[5] Project merge   (build cross-file structures)
       │
       ▼
[6] Persist cache   (per-file entries to disk; project summary in-memory)
```

Steps 1–4 run in parallel across files. Step 5 is single-threaded but
fast (hash-map merges). Step 6 writes per-file cache entries; the
project-level summary is rebuilt every scan from cached entries.

The visitor in step 3 emits:

- One `FileEntry` per file
- One `SymbolEntry` per top-level declaration
- One `ImportEdge` per `import` statement
- One `CallSite` per call expression
- One `FrameworkHint` per file (heuristics + `package.json` + framework-specific config files)

It does *not* extract types, control flow, or expression-level data —
that lives in the AST and is fetched on demand via re-parse.

## Memory model

The whole point of this design is to avoid resident ASTs.

| What's resident | Approximate size |
|---|---|
| `FileEntry` | ~100 bytes/file |
| `SymbolEntry` | ~80 bytes/symbol |
| `ImportEdge` | ~120 bytes/import |
| `CallSite` | ~24 bytes/call |
| `FrameworkHint` | ~16 bytes/file |

For a 100k-file repo with ~10 symbols and ~5 imports per file:

```
files:    100k * 100  =  10MB
symbols:    1M * 80   =  80MB
imports:  500k * 120  =  60MB
calls:      5M * 24   = 120MB
hints:    100k * 16   =   2MB
                       ──────
total:                ~270MB
```

Comfortably under a 1GB working set even on the largest realistic
monorepos. Compare to holding all ASTs resident, which would be
several gigabytes for the same repo.

## Query API

The index exposes a small read-only surface. Rules query through
`RuleContext`, which has access to the live `ProjectIndex`.

```rust
impl ProjectIndex {
    /// Resolve a symbol by name within a file's scope.
    /// Follows re-export chains up to depth 5.
    pub fn resolve(&self, in_file: FileId, name: &str)
        -> Option<&SymbolEntry>;

    /// Where is this symbol defined?
    pub fn definition_of(&self, symbol: SymbolId)
        -> Option<&SymbolEntry>;

    /// All call sites of a function across the project.
    pub fn callers_of(&self, symbol: SymbolId)
        -> impl Iterator<Item = &CallSite>;

    /// What does this file import from `specifier`?
    pub fn imports_of(&self, in_file: FileId, specifier: &str)
        -> Option<&ImportEdge>;

    /// Files that import this symbol from anywhere.
    pub fn importers_of(&self, symbol: SymbolId)
        -> impl Iterator<Item = FileId>;

    /// Framework hint for a file.
    pub fn framework_of(&self, file: FileId)
        -> FrameworkHint;

    /// Re-parse a file on demand. Caller owns the arena and must
    /// drop it before the index borrow ends.
    pub fn reparse(&self, file: FileId)
        -> Result<ParsedFile<'_>, IndexError>;
}
```

The `reparse` method is the controlled escape hatch: when a rule needs
the full AST of a function it's tracing across files, it calls
`reparse(file)` and gets a freshly-parsed file with its own arena.
Caller-managed lifetime keeps the memory model honest.

## Performance targets

| Operation | Cold (p99) | Warm (p99) |
|---|---|---|
| Index build, 100k files | ≤ 5s | ≤ 1s |
| `resolve` query | ≤ 100µs | ≤ 100µs |
| `callers_of` query | ≤ 200µs | ≤ 200µs |
| `reparse` single file | ≤ 5ms | ≤ 2ms |

Cold = no cache, fresh parse of every file. Warm = per-file content
cache hits, only project-summary merge runs.

CI fails if a benchmark on the standard 100k-LoC fixture regresses by
more than 10% on the warm path.

## Cache strategy

Per-file index entries are content-keyed and persisted across scans.
The project summary is rebuilt every scan from cached entries — cheap
once the entries themselves are cached.

```
cache_key = blake3(file_content + parser_version + index_schema_version)
```

`parser_version` invalidates when oxc bumps; `index_schema_version`
invalidates when we add or change entry types.

Storage layers:

1. **In-process** — `dashmap::DashMap<CacheKey, FileIndexEntries>`
   for the duration of a scan (current behavior)
2. 📋 **On-disk** — `~/.cache/stryx/index/` SQLite for repeat scans
   across CLI invocations; entries expire after 30 days unused.
   Phase 3.

Invalidation is implicit: same content + same parser + same schema =
same answer. If any of those change, the hash changes and we re-extract.

## Re-parse on demand

Most cross-file rules don't need the full AST of distant files. They
need to ask the index "is this function imported from a known sanitizer
module?" or "does this symbol have callers in route handlers?" — both
answerable from index entries alone.

A small minority of rules (and the taint engine when it bails on
dynamic dispatch) need to inspect a function body in detail. For these:

```rust
let parsed = ctx.index.reparse(file_id)?;
let function_body = parsed.function_named("validateUser")?;
// ... inspect AST nodes ...
// parsed dropped here; arena freed
```

`reparse` reads from disk cache when available (cached AST is the
source-bytes plus parser-version key, lazily reconstructed). On a 100k
file repo with cold cache, a single `reparse` is ~5ms; warm, ~2ms.
The rule pays for what it queries, no more.

This is the architectural bargain: pay 5s up front to build the index,
then pay 5ms per cross-file zone you actually inspect. Compared to
holding all ASTs resident (multi-GB working set), this is a clear win.

## Adding new index entry types

The index schema is append-only. Adding a new entry type means:

1. Add a new field to `ProjectIndex` and a new struct to the data model
2. Add extraction logic to the per-file visitor
3. Bump `index_schema_version` (forces re-extraction across cached files)
4. Add query methods to the API surface
5. Document the new entry type here
6. Add fixtures showing the entry firing on real code

Removal or renames require a migration plan and an ADR — never silent
schema changes.

## Failure modes

What happens when extraction or queries fail:

- 📋 **Symbol re-export chain too deep (>5 hops)**: mark the symbol
  as `opaque` in the resolve path; log at `warn` level. Cross-file
  rules treat opaque symbols pessimistically (assume taint passes
  through). The current implementation does *one* hop only.
- 📋 **Circular imports**: planned to be detected via Tarjan SCC
  during merge; treated as normal — TypeScript supports them. Symbol
  resolution prefers the file that declares the symbol, not the file
  that re-exports. The current resolver returns `None` on a missing
  hop, which is conservative but loses precision on cycles.
- **Parse failure on a file**: file is excluded from the index entirely
  (no entries contributed); scan continues; we log the file path so
  users can investigate.
- **Cache corruption**: detect via hash mismatch on read; clear the
  affected entry and re-extract. Never crash on cache.
- **Disk cache full**: LRU-evict entries older than 30 days; if still
  full, fall back to in-process-only mode for this scan.
- **`reparse` called after the index borrow ends**: compile error
  (lifetime-enforced). The API is designed so this can't fail at runtime.

## Open questions

- **Cross-package indexing through `node_modules`.** Currently we
  treat npm package imports as opaque (`to_file: None` on the
  `ImportEdge`). Indexing into installed packages would catch supply-
  chain attacks but blows up the index size 10–100×. Defer to Phase 4.
- **Type-aware index.** When type-aware analysis lands (Phase 4 per
  ADR 0003), the index gets a type table mapping symbols to inferred
  types. This will unlock several rules currently parked behind
  "needs type info."
- **Incremental update on file change.** Useful for an LSP server or
  watch-mode CLI; the index already supports per-file content-keyed
  entries, but the project-level summary still rebuilds from scratch
  each scan. A `delta` API is planned but not v0.1.
- **Generic and parameterized symbols.** `function f<T>(x: T): T` —
  the index tracks the symbol but not the type-parameter flow.
  Resolved with the type-aware Phase 4 work.
- **Macros and code generation.** Some Next.js features (Server
  Actions, generated route types) emit symbols that look like they
  exist but only resolve at build time. Treated as opaque for now.

## See also

- [ADR 0003](../decisions/0003-cross-file-and-taint-as-core.md) — why
  cross-file analysis is v0.1 core
- [`taint-engine.md`](taint-engine.md) — the primary consumer of the
  index
- [`ast-pipeline.md`](ast-pipeline.md) — overall scan flow; the index
  build slots in between Step 4 (parse) and Step 5 (rule dispatch)
- [`rule-format.md`](rule-format.md) — the `Rule` trait and how rules
  declare cross-file scope
- [`llm-escalation.md`](llm-escalation.md) — Layer 3 mechanics; LLM
  zones include index-resolved context (callers, defining file,
  framework) in their prompts
- TypeScript Compiler API `Symbol` and `Type` interfaces — reference
  for the semantic primitives we extract
