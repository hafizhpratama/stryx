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
}

impl ProjectIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_file(&mut self, summary: FileSummary) {
        self.files.insert(summary.path.clone(), summary);
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

    /// After all per-file summaries have been inserted, walk every file's
    /// imports and try to resolve each against the indexed files. Only
    /// relative-path specifiers are resolved here; bare specifiers
    /// (npm packages, unmapped aliases) are left unresolved.
    pub fn finalize(&mut self) {
        let mut resolved = HashMap::new();
        for (caller_path, summary) in &self.files {
            for (local_name, import) in &summary.imports {
                if !is_relative_specifier(&import.module_specifier) {
                    continue;
                }
                let Some(target_path) =
                    resolve_relative_path(caller_path, &import.module_specifier, &self.files)
                else {
                    continue;
                };
                resolved.insert(
                    (caller_path.clone(), local_name.clone()),
                    (target_path, import.imported_name.clone()),
                );
            }
        }
        self.resolved = resolved;
    }
}

fn is_relative_specifier(spec: &str) -> bool {
    spec.starts_with("./") || spec.starts_with("../")
}

fn resolve_relative_path(
    caller: &Path,
    specifier: &str,
    files: &HashMap<PathBuf, FileSummary>,
) -> Option<PathBuf> {
    let base = caller.parent()?;
    let mut joined = base.join(specifier);
    // Normalise `./` and `../` segments without touching the filesystem.
    joined = normalise(&joined);

    // 1. Exact match (specifier already includes an extension).
    if files.contains_key(&joined) {
        return Some(joined);
    }
    // 2. With each candidate extension.
    for ext in [".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"] {
        let with_ext = joined.with_extension(&ext[1..]);
        if files.contains_key(&with_ext) {
            return Some(with_ext);
        }
    }
    // 3. As a directory: `<spec>/index.<ext>`.
    for ext in ["ts", "tsx", "js", "jsx", "mts", "cts", "mjs", "cjs"] {
        let with_index = joined.join(format!("index.{ext}"));
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
