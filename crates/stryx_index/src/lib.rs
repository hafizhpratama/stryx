//! Project-level semantic index. Slice 2 populates per-file summaries
//! so cross-file rules can resolve call sites to function bodies in
//! other files. See `docs/architecture/semantic-index.md`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use stryx_taint::ExportedFunctionSummary;

/// Hint about the framework a file participates in. Rules use this to
/// decide whether to engage at all (e.g. Next.js rules skip non-Next files).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FrameworkHint {
    #[default]
    Generic,
    NextJs,
    Hono,
    Express,
    NestJs,
}

/// A binding pulled in from another module via `import { foo } from "./bar"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRef {
    /// Module specifier exactly as written, e.g. `"./lib"`, `"@/lib/db"`,
    /// `"hono"`. Resolution into an absolute file path is the index's job.
    pub module_specifier: String,
    /// Name as exported by the source module. `"default"` for default
    /// imports.
    pub imported_name: String,
}

/// What we know about a class declared at top level. Used so the flow
/// rule can resolve `this.<member>.<method>(arg)` calls inside class
/// methods to the receiving class's method summary, even when the class
/// is defined in another file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassInfo {
    /// Method name → its summary. Constructors and accessors are not
    /// stored here.
    #[serde(default)]
    pub methods: HashMap<String, ExportedFunctionSummary>,
    /// Field/property name → declared TS type name. Populated from
    /// constructor parameter properties (`private readonly userService:
    /// UsersService`) and class field declarations with type annotations
    /// (`private userService: UsersService`).
    #[serde(default)]
    pub field_types: HashMap<String, String>,
}

/// Per-file extract output. Each rule that needs cross-file context
/// contributes data into FileSummary during pass 1.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileSummary {
    pub path: PathBuf,
    #[serde(default)]
    pub framework: FrameworkHint,
    /// Exported functions keyed by their *exported* name (`"default"` for
    /// the default export).
    #[serde(default)]
    pub exports: HashMap<String, ExportedFunctionSummary>,
    /// Top-level functions defined in this file but not exported.
    /// Reachable only from the same file, but worth summarising so
    /// in-file helpers contribute to taint propagation decisions.
    #[serde(default)]
    pub locals: HashMap<String, ExportedFunctionSummary>,
    /// Local-name → ImportRef, e.g. `"createUser"` → `("./lib", "createUser")`.
    #[serde(default)]
    pub imports: HashMap<String, ImportRef>,
    /// Top-level classes keyed by name. Used to resolve
    /// `this.<member>.<method>(...)` calls in NestJS-shaped controllers
    /// where the controller's method delegates to an injected service.
    #[serde(default)]
    pub classes: HashMap<String, ClassInfo>,
    /// Local handler names that are wrapped at export by a function
    /// whose body validates `req.body` (e.g.
    /// `export default validate(handler)` where `validate`'s body
    /// calls `Schema.parse(req.body)`). Inside these handlers,
    /// `flow/unvalidated-body-to-db` suppresses `req.body` as a
    /// taint source — the body has already been schema-checked by
    /// the wrapper.
    #[serde(default)]
    pub body_validated_handlers: std::collections::HashSet<String>,
    /// Names that this file exports by re-exporting from another
    /// module: `export { foo } from "./bar"` becomes
    /// `re_exports["foo"] = ImportRef { "./bar", "foo" }`.
    /// `export { foo as baz } from "./bar"` becomes
    /// `re_exports["baz"] = ImportRef { "./bar", "foo" }`.
    /// Walked by `ProjectIndex::finalize` to chase chains across
    /// barrel files.
    #[serde(default)]
    pub re_exports: HashMap<String, ImportRef>,
    /// Wildcard re-exports: each entry is the source module of an
    /// `export * from "./mod"` statement. The resolver consults
    /// these as a fallback when an exported name isn't directly
    /// in `exports`, `locals`, `classes`, or `re_exports`.
    #[serde(default)]
    pub wildcard_re_exports: Vec<String>,
}

impl FileSummary {
    /// Merge another summary into this one. Used when multiple
    /// rules' extract passes contribute to the same file path.
    /// Existing entries on a conflicting key are kept — rules
    /// touching the same name should agree, and silent
    /// last-writer-wins is the bug `insert_file` previously had.
    pub fn merge_with(&mut self, other: FileSummary) {
        if matches!(self.framework, FrameworkHint::Generic) {
            self.framework = other.framework;
        }
        for (k, v) in other.exports {
            self.exports.entry(k).or_insert(v);
        }
        for (k, v) in other.locals {
            self.locals.entry(k).or_insert(v);
        }
        for (k, v) in other.imports {
            self.imports.entry(k).or_insert(v);
        }
        for (k, v) in other.classes {
            self.classes.entry(k).or_insert(v);
        }
        for (k, v) in other.re_exports {
            self.re_exports.entry(k).or_insert(v);
        }
        for source in other.wildcard_re_exports {
            if !self.wildcard_re_exports.contains(&source) {
                self.wildcard_re_exports.push(source);
            }
        }
        for handler in other.body_validated_handlers {
            self.body_validated_handlers.insert(handler);
        }
    }
}

/// One TypeScript path-alias pattern from `tsconfig.json`'s
/// `compilerOptions.paths`, e.g. `@/*` → `./src/*`. Patterns may
/// include exactly one `*` placeholder; the placeholder's matched
/// substring is substituted into each replacement to produce a
/// candidate file path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathAlias {
    /// Pattern as written in tsconfig, e.g. `"@/*"` or `"~/lib"`.
    pub pattern: String,
    /// Replacement paths, resolved against the project root, e.g.
    /// `["./src/*", "./packages/foo/*"]`. The first replacement that
    /// resolves to an indexed file wins.
    pub replacements: Vec<PathBuf>,
}

/// Project-wide index produced at the end of pass 1. Pass 2 hands a
/// shared reference to each rule via the `RuleContext`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProjectIndex {
    files: HashMap<PathBuf, FileSummary>,
    /// (caller_file, local_name) → (target_file, exported_name). Built by
    /// `finalize` once all per-file summaries are collected.
    #[serde(default)]
    resolved: HashMap<(PathBuf, String), (PathBuf, String)>,
    /// `compilerOptions.paths` from `tsconfig.json` — populated by
    /// the CLI before `finalize`. When a non-relative specifier
    /// matches a pattern, the resolver substitutes and tries each
    /// replacement against the indexed files.
    #[serde(default)]
    path_aliases: Vec<PathAlias>,
}

impl ProjectIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a per-file summary. Multiple rules can each contribute
    /// a summary for the same file during the extract pass — when
    /// they do, the summaries are *merged* field by field rather
    /// than the second clobbering the first. Each map field
    /// (exports, locals, imports, classes, re_exports) takes the
    /// union; conflicting entries on the same key keep the
    /// existing value (rules contributing to the same key are
    /// expected to agree, by convention). The
    /// `body_validated_handlers` set unions; framework hint takes
    /// the first non-default; `wildcard_re_exports` are deduped.
    pub fn insert_file(&mut self, summary: FileSummary) {
        match self.files.entry(summary.path.clone()) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(summary);
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.get_mut().merge_with(summary);
            }
        }
    }

    pub fn file(&self, path: &Path) -> Option<&FileSummary> {
        self.files.get(path)
    }

    pub fn files(&self) -> impl Iterator<Item = &FileSummary> {
        self.files.values()
    }

    /// Resolve a name imported in `caller` into the file + exported name
    /// it ultimately refers to. Returns `None` for unresolved imports
    /// (external packages, unresolvable aliases).
    pub fn resolve(&self, caller: &Path, local_name: &str) -> Option<&FileSummary> {
        let key = (caller.to_path_buf(), local_name.to_string());
        let (target_path, exported_name) = self.resolved.get(&key)?;
        let file = self.files.get(target_path)?;
        // Validate that the resolved export still exists; stale resolves
        // can't produce stale findings.
        if file.exports.contains_key(exported_name) {
            Some(file)
        } else {
            None
        }
    }

    /// Resolve a name imported in `caller` directly to the function summary
    /// it points at, in one step.
    pub fn resolve_summary(
        &self,
        caller: &Path,
        local_name: &str,
    ) -> Option<&ExportedFunctionSummary> {
        let key = (caller.to_path_buf(), local_name.to_string());
        let (target_path, exported_name) = self.resolved.get(&key)?;
        self.files.get(target_path)?.exports.get(exported_name)
    }

    /// Resolve a name imported in `caller` to a class declared in the
    /// target file. Returns the file plus the exported name to look up
    /// inside `file.classes`.
    pub fn resolve_class(&self, caller: &Path, local_name: &str) -> Option<(&FileSummary, &str)> {
        let key = (caller.to_path_buf(), local_name.to_string());
        let (target_path, exported_name) = self.resolved.get(&key)?;
        let file = self.files.get(target_path)?;
        if file.classes.contains_key(exported_name) {
            Some((file, exported_name.as_str()))
        } else {
            None
        }
    }

    /// Configure tsconfig path aliases. Call before `finalize`. The
    /// resolver consults these whenever a specifier isn't relative.
    pub fn set_path_aliases(&mut self, aliases: Vec<PathAlias>) {
        self.path_aliases = aliases;
    }

    /// After all per-file summaries have been inserted, walk every file's
    /// imports and try to resolve each against the indexed files. Both
    /// relative specifiers (`./lib/users`) and tsconfig path-aliased
    /// specifiers (`@/lib/users`) are resolved; bare npm specifiers
    /// (`zod`, `@nestjs/common`) are left unresolved. Chains of
    /// `export { foo } from "./bar"` re-exports and `export *`
    /// wildcard re-exports are followed up to a bounded depth so
    /// barrel files don't break the resolution.
    pub fn finalize(&mut self) {
        let mut resolved = HashMap::new();
        for (caller_path, summary) in &self.files {
            for (local_name, import) in &summary.imports {
                let Some(target_path) = resolve_specifier(
                    caller_path,
                    &import.module_specifier,
                    &self.files,
                    &self.path_aliases,
                ) else {
                    continue;
                };
                let (final_path, final_name) = chase_re_exports(
                    target_path,
                    import.imported_name.clone(),
                    &self.files,
                    &self.path_aliases,
                );
                resolved.insert(
                    (caller_path.clone(), local_name.clone()),
                    (final_path, final_name),
                );
            }
        }
        self.resolved = resolved;
    }
}

/// Follow re-export chains from `(file, name)` until either:
/// - the name is directly defined in `file` (exists in exports /
///   locals / classes), or
/// - the name doesn't appear at all (return what we have — caller
///   handles the missing-export case), or
/// - we hit the depth cap (cycle protection).
fn chase_re_exports(
    mut file: PathBuf,
    mut name: String,
    files: &HashMap<PathBuf, FileSummary>,
    aliases: &[PathAlias],
) -> (PathBuf, String) {
    const MAX_HOPS: usize = 8;
    for _ in 0..MAX_HOPS {
        let Some(summary) = files.get(&file) else {
            return (file, name);
        };
        // Direct hit — the name is concretely defined here.
        if summary.exports.contains_key(&name)
            || summary.locals.contains_key(&name)
            || summary.classes.contains_key(&name)
        {
            return (file, name);
        }
        // Named re-export: `export { name as ... } from "./mod"`.
        if let Some(re) = summary.re_exports.get(&name) {
            if let Some(next_path) = resolve_specifier(&file, &re.module_specifier, files, aliases)
            {
                file = next_path;
                name = re.imported_name.clone();
                continue;
            }
            return (file, name);
        }
        // Wildcard fallback: `export * from "./mod"` — try each
        // wildcard source until one of them declares the name.
        let mut advanced = false;
        for source in &summary.wildcard_re_exports {
            if let Some(next_path) = resolve_specifier(&file, source, files, aliases)
                && let Some(next_summary) = files.get(&next_path)
                && (next_summary.exports.contains_key(&name)
                    || next_summary.locals.contains_key(&name)
                    || next_summary.classes.contains_key(&name)
                    || next_summary.re_exports.contains_key(&name)
                    || !next_summary.wildcard_re_exports.is_empty())
            {
                file = next_path;
                advanced = true;
                break;
            }
        }
        if !advanced {
            return (file, name);
        }
    }
    (file, name)
}

fn is_relative_specifier(spec: &str) -> bool {
    spec.starts_with("./") || spec.starts_with("../")
}

/// Resolves an import specifier — relative *or* tsconfig-aliased — to
/// an indexed file path. Returns None for bare npm specifiers and
/// for aliased specifiers where no replacement maps to an indexed
/// file.
fn resolve_specifier(
    caller: &Path,
    specifier: &str,
    files: &HashMap<PathBuf, FileSummary>,
    aliases: &[PathAlias],
) -> Option<PathBuf> {
    if is_relative_specifier(specifier) {
        return resolve_relative_path(caller, specifier, files);
    }
    for alias in aliases {
        if let Some(rewritten) = apply_alias(alias, specifier) {
            for candidate in rewritten {
                if let Some(found) = resolve_indexed_path(&candidate, files) {
                    return Some(found);
                }
            }
        }
    }
    None
}

/// Match `specifier` against `alias.pattern` and substitute `*` (if
/// present) into each replacement. Returns the candidate paths to
/// try, or None if the pattern doesn't match.
fn apply_alias(alias: &PathAlias, specifier: &str) -> Option<Vec<PathBuf>> {
    let pattern = &alias.pattern;
    let star_at = pattern.find('*');
    match star_at {
        Some(idx) => {
            let prefix = &pattern[..idx];
            let suffix = &pattern[idx + 1..];
            if !specifier.starts_with(prefix) || !specifier.ends_with(suffix) {
                return None;
            }
            let middle = &specifier[prefix.len()..specifier.len() - suffix.len()];
            Some(
                alias
                    .replacements
                    .iter()
                    .map(|r| {
                        let r_str = r.to_string_lossy();
                        let substituted = r_str.replace('*', middle);
                        PathBuf::from(substituted)
                    })
                    .collect(),
            )
        }
        None => {
            // No glob — exact match only.
            if specifier == pattern {
                Some(alias.replacements.clone())
            } else {
                None
            }
        }
    }
}

fn resolve_relative_path(
    caller: &Path,
    specifier: &str,
    files: &HashMap<PathBuf, FileSummary>,
) -> Option<PathBuf> {
    let base = caller.parent()?;
    let joined = normalise(&base.join(specifier));
    resolve_indexed_path(&joined, files)
}

/// Given a normalised path candidate (no `./` / `../`), try the
/// standard TS/JS module resolution dance: exact match, then known
/// extensions, then `<dir>/index.<ext>`. Returns the matched
/// indexed path or None.
fn resolve_indexed_path(
    candidate: &Path,
    files: &HashMap<PathBuf, FileSummary>,
) -> Option<PathBuf> {
    let candidate = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        normalise(candidate)
    };

    if files.contains_key(&candidate) {
        return Some(candidate);
    }
    for ext in ["ts", "tsx", "js", "jsx", "mts", "cts", "mjs", "cjs"] {
        let with_ext = candidate.with_extension(ext);
        if files.contains_key(&with_ext) {
            return Some(with_ext);
        }
    }
    for ext in ["ts", "tsx", "js", "jsx", "mts", "cts", "mjs", "cjs"] {
        let with_index = candidate.join(format!("index.{ext}"));
        if files.contains_key(&with_index) {
            return Some(with_index);
        }
    }
    None
}

fn normalise(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use stryx_core::Span;
    use stryx_taint::ExportedFunctionSummary;

    fn dummy_summary(name: &str) -> ExportedFunctionSummary {
        ExportedFunctionSummary {
            name: name.to_string(),
            params: Vec::new(),
            span: Span::new(PathBuf::from("/fixture.ts"), 0, 0),
            contains_auth_check: false,
            validates_request_body: false,
        }
    }

    #[test]
    fn insert_file_merges_when_paths_collide() {
        // Two rules each contribute their own summary for the same
        // file: rule A populates `exports`, rule B populates
        // `body_validated_handlers`. The result must contain both
        // — the second insert must not clobber the first.
        let path = PathBuf::from("/fixture.ts");

        let mut idx = ProjectIndex::new();
        let mut from_rule_a = FileSummary {
            path: path.clone(),
            ..Default::default()
        };
        from_rule_a
            .exports
            .insert("createUser".into(), dummy_summary("createUser"));
        idx.insert_file(from_rule_a);

        let mut from_rule_b = FileSummary {
            path: path.clone(),
            ..Default::default()
        };
        from_rule_b.body_validated_handlers.insert("handler".into());
        idx.insert_file(from_rule_b);

        let merged = idx.file(&path).expect("merged summary present");
        assert!(
            merged.exports.contains_key("createUser"),
            "rule A's exports were clobbered by rule B's empty exports"
        );
        assert!(
            merged.body_validated_handlers.contains("handler"),
            "rule B's body_validated_handlers were not merged in"
        );
    }

    #[test]
    fn merge_unions_imports_and_re_exports() {
        let path = PathBuf::from("/x.ts");
        let mut idx = ProjectIndex::new();

        let mut a = FileSummary {
            path: path.clone(),
            ..Default::default()
        };
        a.imports.insert(
            "foo".into(),
            ImportRef {
                module_specifier: "./a".into(),
                imported_name: "foo".into(),
            },
        );
        a.wildcard_re_exports.push("./shared".into());
        idx.insert_file(a);

        let mut b = FileSummary {
            path: path.clone(),
            ..Default::default()
        };
        b.imports.insert(
            "bar".into(),
            ImportRef {
                module_specifier: "./b".into(),
                imported_name: "bar".into(),
            },
        );
        b.wildcard_re_exports.push("./shared".into()); // duplicate — should dedupe
        b.wildcard_re_exports.push("./other".into());
        idx.insert_file(b);

        let merged = idx.file(&path).expect("merged");
        assert_eq!(merged.imports.len(), 2);
        assert_eq!(
            merged.wildcard_re_exports,
            vec!["./shared".to_string(), "./other".to_string()],
            "wildcard re-exports must dedupe across merges"
        );
    }
}
