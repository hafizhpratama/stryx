//! Cross-file taint vocabulary. Slice 2 introduces concrete summary
//! types: a per-function record of *what each parameter does to the
//! taint that flows in*. The flow rule consumes these summaries during
//! the second engine pass to follow call sites across files.

use serde::{Deserialize, Serialize};
use stryx_core::Span;

/// A taint label classifies *what kind of trust* flows through a value.
/// Labels are deliberately coarse — a rule reasons over labels, not over
/// raw expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaintLabel {
    /// Anything coming off the network: `req.body`, query string, headers,
    /// form data.
    UserInput,
    /// Authenticated user identity (post-auth subject).
    AuthSubject,
    /// Secret material: API keys, tokens, hashed-but-still-sensitive blobs.
    Secret,
    /// Database row content (may itself be tainted depending on writers).
    DbRow,
}

/// A field/index offset into a tainted parameter. Phase 1 of the
/// shape-lattice migration (ADR 0006): instead of "this whole parameter
/// is tainted," summaries record *which fields/indexes* flow to a sink.
/// Phase 2 absorbs this into a full [`Cell`]/[`Shape`] tree where
/// `Offset` is the key type for [`Shape::Obj`].
///
/// `Field` is JS/TS-aware: `obj.a` and `obj["a"]` yield the same
/// offset, matching Semgrep's `Ofld == Ostr` unification.
///
/// The derived `Ord` is the canonical ordering used by [`Shape::Obj`]'s
/// `BTreeMap` key — Field < Index < Any, with Field and Index sorted
/// by their inner value. Phase 1's `offset_sort_key` helper produces
/// the same ordering and will be retired in slice 2.1c when the
/// flat-`Vec<Offset>` API is replaced by shape-aware queries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Offset {
    /// Named field access: `param.field` or `param["field"]`.
    Field(String),
    /// Constant numeric index: `param[0]`.
    Index(u32),
    /// Non-constant index — `param[i]` where `i` isn't a literal.
    /// Acts as the wildcard "any offset" key in [`Shape::Obj`];
    /// matches Semgrep's `Oany`.
    Any,
}

/// Explicit taint status of a [`Cell`] — Semgrep's `Xtaint.t`. The
/// three cases are deliberately distinguished from "no entry in the
/// shape map":
///
/// - [`Xtaint::None`] — no explicit taint *and* no explicit cleanness;
///   the cell inherits whatever taint a "parent" cell carries. Phase 2
///   invariant: a cell with `xtaint == None` must have a non-`Bot`
///   shape that transitively reaches a `Tainted`/`Clean` cell — an
///   isolated `Cell { None, Bot }` is meaningless and slice 2.1b's
///   canonicalize will remove it.
/// - [`Xtaint::Tainted`] — explicitly tainted with a set of labels.
///   The Vec is treated as a set; insertion-time dedupe is the
///   producer's responsibility, and ordering is normalised on
///   canonicalize.
/// - [`Xtaint::Clean`] — explicitly clean. Phase 2 invariant: a
///   `Clean` cell must have shape `Bot` (any sub-structure is
///   subsumed by the cleanness mark).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Xtaint {
    /// Inherits taint from the surrounding cell. Used as a placeholder
    /// when sub-structure is being tracked but the cell itself has no
    /// direct mark (`x.a := taint` makes `x.a` Tainted but `x` itself
    /// stays None until the analysis decides otherwise).
    None,
    /// Explicit taint with a list of labels. Treat as a set —
    /// duplicates are a producer bug. Empty list means "tainted with
    /// no labels yet known," distinct from `None` semantically: this
    /// cell IS tainted, we just haven't classified the source.
    Tainted(Vec<TaintLabel>),
    /// Explicit cleanness — a sanitiser ran. A `Clean` cell shadows
    /// any inherited taint from parent cells.
    Clean,
}

/// Content-stable identity for a function parameter — the
/// `(function-id, parameter-index)` pair that uniquely names a
/// parameter slot across summaries. Used by [`Shape::Arg`] as the
/// polymorphic-shape-variable identity.
///
/// `fn_id` is the function's stable name (export name for exported
/// functions, mangled `local::name` for locals). `idx` is the
/// 0-based parameter position. Together they're stable across runs
/// so cache keys per ADR 0005 stay valid.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ArgId {
    pub fn_id: String,
    pub idx: u32,
}

/// A taint shape — Semgrep's `shape` from `Shape_and_sig.ml`. A shape
/// approximates the *structure* of a value being tracked, with each
/// reachable cell carrying its own [`Xtaint`].
///
/// Slice 2.1a shipped [`Shape::Bot`] and [`Shape::Obj`]. Slice 2.3
/// adds [`Shape::Arg`] — the polymorphic shape variable, used as a
/// placeholder for "this parameter's shape is whatever the caller
/// passed; we'll instantiate at the call site." The higher-order-
/// function constructor (`Fun`) lands in slice 2.4.
///
/// `Obj` keys are [`Offset`]s, sorted via the derived `Ord` so
/// serialised summaries are deterministic. JS/TS dot-vs-bracket
/// access (`x.a` and `x["a"]`) collapses to the same `Field` offset
/// at construction time per [`Offset`]'s contract.
///
/// On the wire, `Obj` is encoded as a sequence of `[offset, cell]`
/// pairs (sorted by offset) rather than a JSON object, because JSON
/// requires string keys but our key is an enum. The `BTreeMap` shape
/// is preserved in-memory for ergonomic canonicalize logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "data")]
pub enum Shape {
    /// "_|_" — don't know or don't care. Used for primitive values,
    /// untracked sub-structure, and (per the `Clean`-cell invariant)
    /// the body of any explicitly-clean cell.
    Bot,
    /// Struct/dict/tuple-like. Tuples and array-with-constant-index
    /// reads are also recorded here, with `Offset::Index` for
    /// constant indexes and `Offset::Any` for the wildcard. Missing
    /// keys inherit from the surrounding cell's xtaint.
    Obj(#[serde(with = "offset_map_serde")] std::collections::BTreeMap<Offset, Cell>),
    /// Polymorphic shape variable — a placeholder for "this
    /// parameter's shape is whatever the caller passes." The
    /// summary records `Arg(arg_id)` during extraction; consumers
    /// at call sites instantiate the variable with the caller's
    /// actual shape (slice 2.3b will wire that in). Until then,
    /// `Arg` is treated as informational-but-opaque: it is
    /// preserved by canonicalize and merge, contributes no Tainted
    /// leaves, and exposes no visible fields.
    Arg(ArgId),
}

/// Serde adapter that encodes a `BTreeMap<Offset, V>` as a sorted
/// sequence of `[offset, value]` pairs. Required because JSON
/// requires string keys but [`Offset`] is an enum. The output is
/// deterministic (BTreeMap iteration order, which is the derived
/// `Ord` on [`Offset`]) so cache keys per ADR 0005 stay stable.
mod offset_map_serde {
    use super::Offset;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    pub fn serialize<S, V>(map: &BTreeMap<Offset, V>, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        V: Serialize,
    {
        let pairs: Vec<(&Offset, &V)> = map.iter().collect();
        pairs.serialize(ser)
    }

    pub fn deserialize<'de, D, V>(de: D) -> Result<BTreeMap<Offset, V>, D::Error>
    where
        D: Deserializer<'de>,
        V: Deserialize<'de>,
    {
        let pairs: Vec<(Offset, V)> = Vec::deserialize(de)?;
        Ok(pairs.into_iter().collect())
    }
}

/// A "cell" — Semgrep's `cell = Cell of Xtaint.t * shape`. Represents
/// the storage of a value: the [`Xtaint`] mark plus the [`Shape`] of
/// any sub-structure being tracked.
///
/// Phase 2 invariants (enforced by `Cell::canonicalize` in slice
/// 2.1b, documented here so producers can build canonical cells
/// directly when convenient):
///
/// 1. If `xtaint == Xtaint::None`, then `shape` carries information
///    — either a non-empty `Obj` that transitively reaches a
///    `Tainted`/`Clean` cell, or an `Arg(...)` placeholder (slice
///    2.3). Plain `None+Bot` carries no information and is dropped
///    by canonicalize.
/// 2. If `xtaint == Xtaint::Clean`, then `shape == Shape::Bot`.
///    Cleanness shadows sub-structure; any `Obj`/`Arg` content
///    under a `Clean` cell is meaningless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cell {
    pub xtaint: Xtaint,
    pub shape: Shape,
}

impl Cell {
    /// The "bottom" cell — no taint, no structure. Used as the
    /// default starting state and as the canonical leaf for
    /// primitive-typed positions.
    pub fn bot() -> Self {
        Self {
            xtaint: Xtaint::None,
            shape: Shape::Bot,
        }
    }

    /// A cell explicitly tainted with the given labels, no
    /// sub-structure. Convenience for the common "this whole value
    /// just got tainted" case.
    pub fn tainted(labels: Vec<TaintLabel>) -> Self {
        Self {
            xtaint: Xtaint::Tainted(labels),
            shape: Shape::Bot,
        }
    }

    /// An explicitly-clean cell. Per invariant 2, its shape must be
    /// `Bot` — this constructor enforces that at the type level.
    pub fn clean() -> Self {
        Self {
            xtaint: Xtaint::Clean,
            shape: Shape::Bot,
        }
    }

    /// A polymorphic placeholder cell — `None+Arg(id)`. Slice 2.3a of
    /// ADR 0006: emitted by the visitor for parameters with no
    /// observed taint reads, so the summary records the parameter's
    /// identity even when its concrete shape is unknown. Consumers
    /// at call sites (slice 2.3b) will instantiate the placeholder
    /// with whatever shape the caller passed.
    pub fn arg_placeholder(id: ArgId) -> Self {
        Self {
            xtaint: Xtaint::None,
            shape: Shape::Arg(id),
        }
    }

    /// Merge `source` into `self` in place, producing a cell that
    /// reflects the union of taint information from both. Slice 2.1d
    /// of ADR 0006 — the lattice-join used by cross-file
    /// composition (caller absorbing a callee's parameter shape).
    ///
    /// Xtaint join semantics (over-approximating for security):
    ///
    /// - `Tainted(L1) ⊔ Tainted(L2) = Tainted(L1 ∪ L2)` — sorted+deduped
    /// - `Tainted(L) ⊔ None | Clean    = Tainted(L)` — taint dominates
    /// - `None | Clean ⊔ Tainted(L)    = Tainted(L)` — taint dominates
    /// - `Clean ⊔ Clean = Clean`
    /// - `Clean ⊔ None | None ⊔ Clean = None` — only mark Clean if
    ///   both sides agree (we don't yet know the parent's xtaint, so
    ///   downgrading is the conservative choice)
    /// - `None ⊔ None = None`
    ///
    /// Shape join: `Bot` is the identity, and `Obj` maps merge by
    /// key with recursive cell-merge on shared keys. The result is
    /// not necessarily canonical — call [`Cell::canonicalize`] after
    /// a sequence of merges to restore minimality.
    pub fn merge_into(&mut self, source: &Cell) {
        // Xtaint join.
        self.xtaint = merge_xtaint(&self.xtaint, &source.xtaint);
        // Shape join. Concrete `Obj` beats opaque `Arg` beats `Bot`.
        // Two `Arg`s with the same id collapse to one; different ids
        // fall back to `Bot` (we don't have a representation for "two
        // different polymorphic placeholders" — slice 2.3b can revisit
        // when a producer comes online).
        match (&source.shape, &mut self.shape) {
            (Shape::Bot, _) => { /* nothing to add */ }
            (src @ Shape::Obj(_), Shape::Bot | Shape::Arg(_)) => {
                self.shape = src.clone();
            }
            (Shape::Obj(s_map), Shape::Obj(t_map)) => {
                for (off, s_cell) in s_map {
                    let t_cell = t_map.entry(off.clone()).or_insert_with(Cell::bot);
                    t_cell.merge_into(s_cell);
                }
            }
            (src @ Shape::Arg(_), Shape::Bot) => {
                self.shape = src.clone();
            }
            (Shape::Arg(s_id), Shape::Arg(t_id)) => {
                if s_id != t_id {
                    // Different placeholders — conservatively drop to Bot.
                    self.shape = Shape::Bot;
                }
                // Same id: leave self alone (already Arg(t_id)).
            }
            (Shape::Arg(_), Shape::Obj(_)) => { /* concrete wins; leave self */ }
        }
    }

    /// Replace every `Xtaint::Tainted(_)` cell reachable through
    /// this cell with `replacement`'s xtaint and shape, merging the
    /// existing sub-structure into the replacement. Slice 3.4 of
    /// ADR 0007 — the substitution primitive used to instantiate a
    /// callee's `return_shape` with the caller's shape for the
    /// matching argument.
    ///
    /// In Phase 3 model: `return_shape` carries `Tainted+Bot` leaves
    /// at the offsets where the param's value flows out. At a call
    /// site, the caller's shape for the arg passed in slot `idx`
    /// becomes the substitution target. Substituting "Tainted at
    /// offset chain in return_shape" with "caller's arg shape"
    /// produces the caller-side view of the call's result.
    ///
    /// Recursion: walks `Obj` cells to find Tainted leaves. `Arg`
    /// and `Bot` shapes are unchanged; their xtaint side is also
    /// unchanged unless it's `Tainted`, in which case it gets the
    /// replacement.
    ///
    /// **Wiring status (honest):** the cross-file consumer (slice
    /// 3.5) needs per-local shape tracking before this primitive
    /// can be applied at `const x = helper(arg)` sites. The visitor
    /// today tracks only `HashSet<String>` of tainted names; the
    /// jump to `HashMap<String, Cell>` is a multi-hundred-line
    /// refactor deferred to its own slice. This primitive ships
    /// here as substrate that slice 3.5 will consume.
    pub fn instantiate_tainted(&mut self, replacement: &Cell) {
        if matches!(self.xtaint, Xtaint::Tainted(_)) {
            let original_shape = std::mem::replace(&mut self.shape, Shape::Bot);
            if matches!(original_shape, Shape::Bot) {
                // No sub-structure to preserve; just take the
                // replacement wholesale.
                *self = replacement.clone();
            } else {
                // Has sub-structure; merge the replacement with it.
                // Wraps the original shape in a None+Obj cell so the
                // merge respects that we want to KEEP the structure,
                // not let it shadow the replacement's xtaint.
                let mut new_self = replacement.clone();
                new_self.merge_into(&Cell {
                    xtaint: Xtaint::None,
                    shape: original_shape,
                });
                *self = new_self;
            }
            return;
        }
        if let Shape::Obj(map) = &mut self.shape {
            for cell in map.values_mut() {
                cell.instantiate_tainted(replacement);
            }
        }
    }

    /// Replace every `Shape::Arg(id)` reachable through this cell
    /// where `id.fn_id == fn_id_to_strip` with `Shape::Bot`. Slice
    /// 2.3b of ADR 0006 — the instantiation primitive used to
    /// remove a callee's polymorphic placeholders before grafting
    /// the callee's shape into a caller's tree.
    ///
    /// **Wiring status (honest):** the cross-file site in
    /// `flow/unvalidated-body-to-db` only fires when the callee
    /// recorded at least one sink observation, which means the
    /// callee's shape is concrete (`Tainted+Bot` or `Obj{...}`),
    /// never `Arg`. So this helper is not yet called in production —
    /// it lives here as the substrate that future slices with
    /// return-shape tracking (where `Arg` *does* propagate into
    /// caller-visible shapes) will need.
    pub fn strip_arg_for(&mut self, fn_id_to_strip: &str) {
        if let Shape::Arg(id) = &self.shape
            && id.fn_id == fn_id_to_strip
        {
            self.shape = Shape::Bot;
            return;
        }
        if let Shape::Obj(map) = &mut self.shape {
            for cell in map.values_mut() {
                cell.strip_arg_for(fn_id_to_strip);
            }
        }
    }

    /// True iff any cell reachable through this one has
    /// `Xtaint::Tainted`. Slice 2.5 of ADR 0006 — the derivation
    /// rule for the legacy `reaches_db_sink_unsanitized` boolean.
    pub fn has_tainted_leaf(&self) -> bool {
        self.count_tainted_leaves() > 0
    }

    /// Top-level field/index offsets that are themselves tainted or
    /// have a Tainted descendant. Returns the same set Phase 1's
    /// `top_offsets_seen` recorded directly: when the visitor saw
    /// `body.where.id` flow to a sink, this returns
    /// `[Field("where")]` (the field closest to the base, not the
    /// leaf). Slice 2.5 of ADR 0006 — the derivation rule for the
    /// legacy `tainted_offsets` field.
    ///
    /// Returns `[]` for whole-value taint (`Tainted+Bot`) and for
    /// non-`Obj` shapes (`Bot`, `Arg`).
    pub fn top_tainted_offsets(&self) -> Vec<Offset> {
        match &self.shape {
            Shape::Obj(map) => map
                .iter()
                .filter(|(_, cell)| cell.has_tainted_leaf())
                .map(|(off, _)| off.clone())
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Recursively count Tainted leaves reachable through this cell.
    /// Used by [`ConvergenceSignal::tainted_leaf_total`] in
    /// `stryx_cli` to detect shape growth across fix-point
    /// iterations — a monotone-non-decreasing axis under the visitor's
    /// observation-only producer (it never adds Clean cells, so the
    /// count only grows). Per ADR 0004's contract, every summary
    /// axis that can change must be in the convergence tuple.
    pub fn count_tainted_leaves(&self) -> usize {
        let here = matches!(self.xtaint, Xtaint::Tainted(_)) as usize;
        let nested = match &self.shape {
            Shape::Bot => 0,
            Shape::Arg(_) => 0,
            Shape::Obj(map) => map.values().map(Self::count_tainted_leaves).sum(),
        };
        here + nested
    }

    /// Bring `self` into canonical form per the two Phase 2
    /// invariants documented on [`Cell`], returning `None` if the
    /// cell carries no information and should be dropped from its
    /// parent map. Recursive — every reachable sub-cell is also
    /// canonicalized.
    ///
    /// What canonicalize does:
    ///
    /// 1. **Invariant 2 — `Clean ⇒ Bot`**: a `Clean` cell's shape is
    ///    flattened to `Bot`. Sub-structure under a clean cell is
    ///    semantically subsumed by the cleanness mark.
    /// 2. **Label-set normalization**: a `Tainted(labels)` cell's
    ///    label list is sorted and de-duplicated so cache keys per
    ///    ADR 0005 are insertion-order-independent.
    /// 3. **Recursive shape canonicalization**: each entry in an
    ///    `Obj` map is canonicalized; entries that resolve to `None`
    ///    are dropped. An `Obj` whose entries all dropped collapses
    ///    to `Shape::Bot`.
    /// 4. **Invariant 1 — `None + Bot ⇒ drop`**: a cell whose
    ///    `xtaint` is `None` and whose (post-recursion) shape is
    ///    `Bot` carries no information — return `None` so the
    ///    parent omits it from its map.
    ///
    /// Idempotence: `canonicalize(canonicalize(c))` produces the
    /// same result as `canonicalize(c)`. The property test
    /// `cell_canonicalize_idempotent` enforces this on a
    /// representative shape.
    pub fn canonicalize(self) -> Option<Self> {
        let Self { xtaint, shape } = self;
        // Invariant 2: Clean shadows any sub-structure.
        if matches!(xtaint, Xtaint::Clean) {
            return Some(Self {
                xtaint,
                shape: Shape::Bot,
            });
        }
        // Normalise Tainted's label list.
        let xtaint = match xtaint {
            Xtaint::Tainted(mut labels) => {
                labels.sort();
                labels.dedup();
                Xtaint::Tainted(labels)
            }
            other => other,
        };
        let shape = canonicalize_shape(shape);
        // Invariant 1: None + Bot is meaningless — drop. None + Arg
        // is preserved (the placeholder identity is information).
        match (&xtaint, &shape) {
            (Xtaint::None, Shape::Bot) => None,
            _ => Some(Self { xtaint, shape }),
        }
    }
}

/// Lattice-join on [`Xtaint`] — used by [`Cell::merge_into`] when
/// combining two taint observations. Tainted dominates; Clean
/// requires agreement on both sides; None is the identity.
/// Documented in detail on `Cell::merge_into`.
fn merge_xtaint(a: &Xtaint, b: &Xtaint) -> Xtaint {
    match (a, b) {
        (Xtaint::Tainted(l1), Xtaint::Tainted(l2)) => {
            let mut combined: Vec<TaintLabel> = l1.iter().chain(l2.iter()).copied().collect();
            combined.sort();
            combined.dedup();
            Xtaint::Tainted(combined)
        }
        (Xtaint::Tainted(l), _) | (_, Xtaint::Tainted(l)) => Xtaint::Tainted(l.clone()),
        (Xtaint::Clean, Xtaint::Clean) => Xtaint::Clean,
        // Clean + None: conservative — only retain Clean if both
        // sides agree. The None side might inherit Tainted from a
        // parent, which would dominate Clean anyway.
        (Xtaint::Clean, Xtaint::None) | (Xtaint::None, Xtaint::Clean) => Xtaint::None,
        (Xtaint::None, Xtaint::None) => Xtaint::None,
    }
}

/// Canonicalize a [`Shape`]. Recursive helper for
/// [`Cell::canonicalize`]; an empty `Obj` (after entry-pruning)
/// collapses to `Bot`. `Arg` is preserved as-is — it's a
/// placeholder identity that is meaningful even without internal
/// structure (slice 2.3 of ADR 0006).
fn canonicalize_shape(shape: Shape) -> Shape {
    match shape {
        Shape::Bot => Shape::Bot,
        Shape::Arg(id) => Shape::Arg(id),
        Shape::Obj(map) => {
            let pruned: std::collections::BTreeMap<Offset, Cell> = map
                .into_iter()
                .filter_map(|(off, cell)| cell.canonicalize().map(|c| (off, c)))
                .collect();
            if pruned.is_empty() {
                Shape::Bot
            } else {
                Shape::Obj(pruned)
            }
        }
    }
}

/// What happens to taint that enters a function through a single
/// parameter. Per-rule for now — the flow rule populates this for the
/// `UserInput` label.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParamFlow {
    /// Position-indexed name of the parameter (informational).
    pub name: String,
    /// True iff there is a control-flow path from this parameter to a
    /// DB write call where no sanitizer (`.parse`/`.safeParse`) cleared
    /// the taint along the way.
    ///
    /// Slice-1 transitional state per ADR 0006 — coexists with
    /// [`tainted_offsets`](Self::tainted_offsets) until slice 2 starts
    /// populating offsets and slice 3 collapses this field into a
    /// derived accessor (`!self.tainted_offsets.is_empty()`).
    pub reaches_db_sink_unsanitized: bool,
    /// True iff there is a control-flow path from this parameter to an
    /// outbound HTTP call (`fetch` / `axios.<m>` / `got`) used as the
    /// URL argument, with no recognised URL allow-list sanitiser along
    /// the way. Populated by `flow/ssrf-via-fetch`'s slice 2 extract
    /// pass. Pre-slice-2 cache entries and rules that don't write to
    /// this flag leave it `false` (serde default).
    #[serde(default)]
    pub reaches_fetch_sink_unsanitized: bool,
    /// True iff *every* fetch sink the parameter reaches inside the
    /// callee uses a host-pinned URL template — either a literal
    /// scheme+host leading quasi (`https://example.com/...`) or an
    /// operator-controlled host interpolation (`${process.env.X}/...`).
    /// In that shape the parameter can only inject into the path/query
    /// of a fixed host, so the call-site finding downgrades from High
    /// (full SSRF) to Medium (path-injection). Only meaningful when
    /// [`reaches_fetch_sink_unsanitized`](Self::reaches_fetch_sink_unsanitized)
    /// is true. Pre-precision-fix cache entries leave it `false`
    /// (serde default), which conservatively keeps the High tier.
    #[serde(default)]
    pub fetch_sink_path_pinned_only: bool,
    /// True iff there is a control-flow path from this parameter to a
    /// redirect call (`NextResponse.redirect`, bare `redirect`,
    /// `res.redirect`, `Response.redirect`) used as the target URL,
    /// with no recognised URL allow-list sanitiser along the way.
    /// Populated by `flow/redirect-open`'s slice 2 extract pass.
    /// Pre-slice-2 cache entries and rules that don't write to this
    /// flag leave it `false` (serde default).
    #[serde(default)]
    pub reaches_redirect_sink_unsanitized: bool,
    /// Which field/index offsets of this parameter flow to a sink, if
    /// the rule populating the summary records that detail. Empty list
    /// means either "no taint reaches a sink" or "the rule has not yet
    /// migrated to record offsets" — disambiguate via
    /// [`reaches_db_sink_unsanitized`](Self::reaches_db_sink_unsanitized)
    /// during the slice-1/2 window.
    ///
    /// See ADR 0006 (shape lattice) for the migration plan.
    #[serde(default)]
    pub tainted_offsets: Vec<Offset>,
    /// Phase 2 of ADR 0006 — full-chain shape of how this parameter
    /// flows. `Some(canonical_cell)` when the visitor recorded any
    /// taint observations; `None` when nothing reached a sink. The
    /// shape captures field/index *chains* — `body.where.id` produces
    /// `Cell { None, Obj { where -> Cell { None, Obj { id -> Cell { Tainted, Bot } } } } }`
    /// — beyond what the flat `tainted_offsets` first-field list can
    /// express. Slice 2.1c populates it from the local-sink site only;
    /// cross-file shape composition lands in slice 2.1d. No consumer
    /// reads this yet — the boolean and `tainted_offsets` remain the
    /// source of truth through Phase 2's observation-only window.
    #[serde(default)]
    pub param_shape: Option<Cell>,
    /// Phase 3 of ADR 0007 — shape of what flows through the
    /// function's return value when *this param* is tainted. Recorded
    /// per-param-simulation: each visitor sees one parameter as
    /// pre-tainted at function entry, observes return statements'
    /// argument expressions, and records the chain at which the
    /// tainted value flows to the leaf.
    ///
    /// `function passthrough(b) { return b; }` records
    /// `Cell { Tainted, Bot }` (whole-value flows). `function pick(b)
    /// { return b.id; }` records `Cell { None, Obj { id: Tainted+Bot } }`
    /// (id-offset flows). `function noop() { return 42; }` records
    /// `None` (nothing tainted flows out).
    ///
    /// Slice 3.1 (this slice) populates it from local return
    /// statements only. Cross-file return-shape propagation and
    /// `Cell::instantiate_arg`-driven precision land in slices
    /// 3.4–3.5 per ADR 0007. No consumer reads this yet; the
    /// existing `propagates_to_return: bool` remains the source of
    /// truth through Phase 3's observation-only window.
    #[serde(default)]
    pub return_shape: Option<Cell>,
    /// True iff the parameter's value flows back to the function's
    /// return value (directly, or via member access / object/array
    /// literal containment). Helpers like `toPaymentStatus(input)`
    /// that only return constant strings have this set to false, so
    /// callers don't propagate taint through them.
    #[serde(default)]
    pub propagates_to_return: bool,
    /// Where the sink lives, if known. Used so call-site findings can
    /// point readers to the actual write inside the callee.
    pub sink_span: Option<Span>,
}

/// Summary of a single exported function. The flow rule produces one of
/// these per top-level/exported function during the extract pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedFunctionSummary {
    pub name: String,
    pub params: Vec<ParamFlow>,
    /// Span of the function definition itself, for diagnostics.
    pub span: Span,
    /// True iff the function's body contains a recognised auth-helper
    /// call (`getServerSession`, `auth`, `getSession`, …). Consumed by
    /// `flow/auth-bypass-via-wrapper` to tell apart wrappers that
    /// actually verify authentication from no-op wrappers that just
    /// claim to.
    #[serde(default)]
    pub contains_auth_check: bool,
    /// True iff the function's body validates `req.body` against a
    /// schema before calling its inner handler — the inverse of
    /// `contains_auth_check`. Consumed by `flow/unvalidated-body-to-db`
    /// to suppress body-taint sourcing inside handlers wrapped by a
    /// `validate(handler)`-shaped function whose body calls
    /// `<schema>.parse(req.body)` or `<schema>.safeParse(...)`.
    #[serde(default)]
    pub validates_request_body: bool,
}

impl ExportedFunctionSummary {
    /// True if calling this function with a tainted value at parameter
    /// position `idx` would result in that taint reaching a DB sink.
    pub fn taints_through_param(&self, idx: usize) -> bool {
        self.params
            .get(idx)
            .is_some_and(|p| p.reaches_db_sink_unsanitized)
    }

    /// True if calling this function with a tainted value at parameter
    /// position `idx` would result in that taint reaching an outbound
    /// HTTP call (`fetch`/`axios`/`got`) as the URL — i.e. a
    /// cross-file SSRF.
    pub fn taints_through_fetch_param(&self, idx: usize) -> bool {
        self.params
            .get(idx)
            .is_some_and(|p| p.reaches_fetch_sink_unsanitized)
    }

    /// True if calling this function with a tainted value at parameter
    /// position `idx` would result in that taint reaching a redirect
    /// call as the target URL — i.e. a cross-file open redirect.
    pub fn taints_through_redirect_param(&self, idx: usize) -> bool {
        self.params
            .get(idx)
            .is_some_and(|p| p.reaches_redirect_sink_unsanitized)
    }

    /// Merge per-rule sink flags from `other` into `self`. Used when
    /// multiple rules' extract passes produce summaries for the same
    /// export name — each rule populates its own `reaches_*_sink_*`
    /// flag, and the merged summary must carry all of them so the
    /// run pass can answer cross-file queries for every rule.
    ///
    /// Only the per-rule sink flags are unioned. Richer fields
    /// (`tainted_offsets`, `param_shape`, `return_shape`,
    /// `propagates_to_return`, `sink_span`) are left at their existing
    /// values — by convention the rule that produced the more
    /// sophisticated shape is the one whose summary was inserted
    /// first, and slice 2 of SSRF/redirect-open deliberately doesn't
    /// populate shapes (the simpler simulator only records
    /// reachability).
    pub fn merge_per_rule_flags(&mut self, other: &ExportedFunctionSummary) {
        self.contains_auth_check |= other.contains_auth_check;
        self.validates_request_body |= other.validates_request_body;
        for (i, other_p) in other.params.iter().enumerate() {
            if let Some(p) = self.params.get_mut(i) {
                p.reaches_db_sink_unsanitized |= other_p.reaches_db_sink_unsanitized;
                // `fetch_sink_path_pinned_only` is "every sink is
                // pinned"; merging two summaries that each reach
                // fetch keeps the pinned-only tier iff BOTH did.
                // Crucially, if `other` doesn't add a fetch reach,
                // it carries no opinion — preserve `self`'s flag.
                if other_p.reaches_fetch_sink_unsanitized {
                    if p.reaches_fetch_sink_unsanitized {
                        p.fetch_sink_path_pinned_only &= other_p.fetch_sink_path_pinned_only;
                    } else {
                        p.fetch_sink_path_pinned_only = other_p.fetch_sink_path_pinned_only;
                    }
                }
                p.reaches_fetch_sink_unsanitized |= other_p.reaches_fetch_sink_unsanitized;
                p.reaches_redirect_sink_unsanitized |= other_p.reaches_redirect_sink_unsanitized;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_serde_roundtrips() {
        let offsets = vec![
            Offset::Field("body".into()),
            Offset::Field("where".into()),
            Offset::Index(0),
            Offset::Any,
        ];
        let json = serde_json::to_string(&offsets).unwrap();
        let back: Vec<Offset> = serde_json::from_str(&json).unwrap();
        assert_eq!(offsets, back);
    }

    #[test]
    fn paramflow_with_empty_offsets_deserializes_from_pre_slice1_json() {
        // Pre-slice-1 cache entries have no `tainted_offsets` key.
        // They must still deserialize, with the field defaulting to
        // empty — a safe under-approximation per the slice-1
        // transitional contract. Guards the cache-rollover behaviour
        // from ADR 0005.
        let pre = r#"{
            "name": "handler",
            "reaches_db_sink_unsanitized": true,
            "propagates_to_return": false
        }"#;
        let pf: ParamFlow = serde_json::from_str(pre).unwrap();
        assert!(pf.reaches_db_sink_unsanitized);
        assert!(pf.tainted_offsets.is_empty());
    }

    #[test]
    fn paramflow_deserializes_pre_slice2_json_without_fetch_flag() {
        // Cache entries written before slice 2 of flow/ssrf-via-fetch
        // landed have no `reaches_fetch_sink_unsanitized` key. They
        // must still deserialize, with the field defaulting to false
        // — same cache-rollover contract as `tainted_offsets` (ADR
        // 0005). Under-approximating is safe: a missing fetch flag
        // just means the cross-file SSRF finding is silently skipped
        // until the next extract pass rewrites the summary.
        let pre = r#"{
            "name": "fetchHelper",
            "reaches_db_sink_unsanitized": false,
            "propagates_to_return": false
        }"#;
        let pf: ParamFlow = serde_json::from_str(pre).unwrap();
        assert!(!pf.reaches_db_sink_unsanitized);
        assert!(!pf.reaches_fetch_sink_unsanitized);
    }

    #[test]
    fn taints_through_fetch_param_reads_the_fetch_flag_only() {
        // The two per-rule sink flags are independent — a param can
        // taint to a DB sink without tainting to a fetch sink, and
        // vice versa. The accessor must read its own flag.
        let summary = ExportedFunctionSummary {
            name: "h".into(),
            params: vec![
                ParamFlow {
                    name: "p0".into(),
                    reaches_db_sink_unsanitized: true,
                    reaches_fetch_sink_unsanitized: false,
                    ..Default::default()
                },
                ParamFlow {
                    name: "p1".into(),
                    reaches_db_sink_unsanitized: false,
                    reaches_fetch_sink_unsanitized: true,
                    ..Default::default()
                },
            ],
            span: Span::new(std::path::PathBuf::new(), 0, 0),
            contains_auth_check: false,
            validates_request_body: false,
        };
        assert!(summary.taints_through_param(0));
        assert!(!summary.taints_through_fetch_param(0));
        assert!(!summary.taints_through_param(1));
        assert!(summary.taints_through_fetch_param(1));
    }

    #[test]
    fn offset_ord_matches_phase1_sort_key() {
        // Phase 1's `offset_sort_key` defined Field < Index < Any, with
        // Field/Index sorted by inner value. The derived `Ord` on
        // `Offset` (which BTreeMap uses) must match — otherwise
        // serialised summaries from Phase 1 would deserialize into a
        // differently-ordered tree on Phase 2 readback.
        let mut items = vec![
            Offset::Any,
            Offset::Index(2),
            Offset::Field("z".into()),
            Offset::Index(0),
            Offset::Field("a".into()),
        ];
        items.sort();
        assert_eq!(
            items,
            vec![
                Offset::Field("a".into()),
                Offset::Field("z".into()),
                Offset::Index(0),
                Offset::Index(2),
                Offset::Any,
            ],
        );
    }

    #[test]
    fn cell_constructors_produce_canonical_shapes() {
        // The three convenience constructors must satisfy the Phase 2
        // invariants documented on `Cell`. `bot()` is non-canonical
        // by design (xtaint=None + shape=Bot violates invariant 1),
        // and slice 2.1b's canonicalize will reject/erase it from a
        // parent map; here we just check the constructor produces
        // what its name claims.
        assert_eq!(
            Cell::bot(),
            Cell {
                xtaint: Xtaint::None,
                shape: Shape::Bot
            }
        );
        let t = Cell::tainted(vec![TaintLabel::UserInput]);
        assert_eq!(t.xtaint, Xtaint::Tainted(vec![TaintLabel::UserInput]));
        assert_eq!(t.shape, Shape::Bot);
        // Invariant 2 is structural: `Cell::clean()` always emits Bot.
        let c = Cell::clean();
        assert_eq!(c.xtaint, Xtaint::Clean);
        assert_eq!(c.shape, Shape::Bot);
    }

    #[test]
    fn shape_serde_roundtrips_through_obj_with_nested_cells() {
        use std::collections::BTreeMap;
        // Construct a representative shape: an outer Obj with two
        // fields, one tainted (Tainted/Bot) and one with a nested Obj
        // tracking a single sub-field. Round-trip through JSON and
        // assert equality.
        let mut inner_map = BTreeMap::new();
        inner_map.insert(
            Offset::Field("nested".into()),
            Cell::tainted(vec![TaintLabel::UserInput]),
        );
        let mut outer_map = BTreeMap::new();
        outer_map.insert(
            Offset::Field("a".into()),
            Cell::tainted(vec![TaintLabel::UserInput]),
        );
        outer_map.insert(
            Offset::Field("b".into()),
            Cell {
                xtaint: Xtaint::None,
                shape: Shape::Obj(inner_map),
            },
        );
        let cell = Cell {
            xtaint: Xtaint::None,
            shape: Shape::Obj(outer_map),
        };
        let json = serde_json::to_string(&cell).unwrap();
        let back: Cell = serde_json::from_str(&json).unwrap();
        assert_eq!(cell, back);
    }

    #[test]
    fn xtaint_serde_distinguishes_none_clean_and_tainted() {
        // The three Xtaint variants have semantically distinct cache
        // implications, so their serialised forms must round-trip
        // unambiguously. This guards against accidental serde rename
        // collisions during future label-set additions.
        for x in [
            Xtaint::None,
            Xtaint::Clean,
            Xtaint::Tainted(vec![]),
            Xtaint::Tainted(vec![TaintLabel::UserInput, TaintLabel::Secret]),
        ] {
            let json = serde_json::to_string(&x).unwrap();
            let back: Xtaint = serde_json::from_str(&json).unwrap();
            assert_eq!(x, back);
        }
    }

    // ── Canonicalize tests (slice 2.1b of ADR 0006) ─────────────────────

    /// Build an `Obj` cell from a list of (offset, cell) pairs.
    /// Convenience for the canonicalize tests; not part of the
    /// public API.
    fn obj(entries: Vec<(Offset, Cell)>) -> Cell {
        let mut map = std::collections::BTreeMap::new();
        for (off, cell) in entries {
            map.insert(off, cell);
        }
        Cell {
            xtaint: Xtaint::None,
            shape: Shape::Obj(map),
        }
    }

    #[test]
    fn canonicalize_drops_bare_bot_cell() {
        // Invariant 1: None + Bot ⇒ drop.
        assert_eq!(Cell::bot().canonicalize(), None);
    }

    #[test]
    fn canonicalize_keeps_tainted_cell() {
        let t = Cell::tainted(vec![TaintLabel::UserInput]);
        assert_eq!(t.clone().canonicalize(), Some(t));
    }

    #[test]
    fn canonicalize_flattens_clean_cell_with_substructure() {
        // Invariant 2: Clean ⇒ Bot. Any pre-existing Obj content is
        // erased.
        let c = Cell {
            xtaint: Xtaint::Clean,
            shape: Shape::Obj({
                let mut m = std::collections::BTreeMap::new();
                m.insert(
                    Offset::Field("a".into()),
                    Cell::tainted(vec![TaintLabel::UserInput]),
                );
                m
            }),
        };
        assert_eq!(c.canonicalize(), Some(Cell::clean()));
    }

    #[test]
    fn canonicalize_normalises_tainted_label_list() {
        // Labels arrive in arbitrary order with possible duplicates;
        // canonicalize must sort + dedupe so cache keys are stable.
        let unsorted = Cell {
            xtaint: Xtaint::Tainted(vec![
                TaintLabel::Secret,
                TaintLabel::UserInput,
                TaintLabel::Secret,
                TaintLabel::AuthSubject,
            ]),
            shape: Shape::Bot,
        };
        let canonical = unsorted.canonicalize().expect("non-None");
        assert_eq!(
            canonical.xtaint,
            Xtaint::Tainted(vec![
                TaintLabel::UserInput,
                TaintLabel::AuthSubject,
                TaintLabel::Secret,
            ]),
        );
    }

    #[test]
    fn canonicalize_prunes_useless_obj_entries_recursively() {
        // Outer cell holds an Obj with two entries. One entry is a
        // bare-bot leaf (drops via invariant 1); the other is a
        // tainted leaf (stays). After pruning, the Obj has one entry,
        // so the outer None+Obj still has structure and stays.
        let c = obj(vec![
            (Offset::Field("useless".into()), Cell::bot()),
            (
                Offset::Field("real".into()),
                Cell::tainted(vec![TaintLabel::UserInput]),
            ),
        ]);
        let canonical = c.canonicalize().expect("not dropped");
        match &canonical.shape {
            Shape::Obj(map) => {
                assert_eq!(map.len(), 1);
                assert!(map.contains_key(&Offset::Field("real".into())));
            }
            other => panic!("expected Obj, got {other:?}"),
        }
    }

    #[test]
    fn canonicalize_drops_obj_when_all_entries_useless() {
        // Outer None+Obj where every entry is a bare-bot leaf — the
        // Obj prunes to empty, collapses to Bot, then the outer cell
        // is None+Bot which drops.
        let c = obj(vec![
            (Offset::Field("a".into()), Cell::bot()),
            (Offset::Field("b".into()), Cell::bot()),
        ]);
        assert_eq!(c.canonicalize(), None);
    }

    #[test]
    fn canonicalize_collapses_obj_with_only_clean_to_clean_outer() {
        // Edge case: an outer None+Obj whose only entry is a Clean
        // leaf. The Clean cell stays (Cleanness is information),
        // so the outer Obj keeps it, so the outer cell stays.
        let c = obj(vec![(Offset::Field("a".into()), Cell::clean())]);
        let canonical = c.canonicalize().expect("not dropped");
        match &canonical.shape {
            Shape::Obj(map) => {
                assert_eq!(map.len(), 1);
                assert_eq!(map.get(&Offset::Field("a".into())), Some(&Cell::clean()));
            }
            other => panic!("expected Obj with Clean leaf, got {other:?}"),
        }
    }

    // ── merge_into tests (slice 2.1d of ADR 0006) ───────────────────────

    #[test]
    fn merge_into_xtaint_tainted_unions_label_sets() {
        let mut t = Cell::tainted(vec![TaintLabel::UserInput]);
        t.merge_into(&Cell::tainted(vec![
            TaintLabel::Secret,
            TaintLabel::UserInput,
        ]));
        // Sorted + de-duped.
        assert_eq!(
            t.xtaint,
            Xtaint::Tainted(vec![TaintLabel::UserInput, TaintLabel::Secret])
        );
    }

    #[test]
    fn merge_into_xtaint_tainted_dominates_clean_and_none() {
        let mut none = Cell::bot();
        none.merge_into(&Cell::tainted(vec![TaintLabel::UserInput]));
        assert_eq!(none.xtaint, Xtaint::Tainted(vec![TaintLabel::UserInput]));

        let mut clean = Cell::clean();
        clean.merge_into(&Cell::tainted(vec![TaintLabel::Secret]));
        assert_eq!(clean.xtaint, Xtaint::Tainted(vec![TaintLabel::Secret]));
    }

    #[test]
    fn merge_into_clean_plus_none_downgrades_to_none() {
        // Conservative: only mark Clean if both sides agree. The
        // None side might still inherit Tainted from a parent, in
        // which case Clean would be wrong.
        let mut clean = Cell::clean();
        clean.merge_into(&Cell::bot());
        assert_eq!(clean.xtaint, Xtaint::None);
    }

    #[test]
    fn merge_into_obj_unions_keys_and_recurses() {
        // target = Obj{ a: Tainted }
        // source = Obj{ b: Tainted }
        // result = Obj{ a: Tainted, b: Tainted }
        let mut target = obj(vec![(
            Offset::Field("a".into()),
            Cell::tainted(vec![TaintLabel::UserInput]),
        )]);
        let source = obj(vec![(
            Offset::Field("b".into()),
            Cell::tainted(vec![TaintLabel::UserInput]),
        )]);
        target.merge_into(&source);
        match &target.shape {
            Shape::Obj(map) => {
                assert_eq!(map.len(), 2);
                assert!(map.contains_key(&Offset::Field("a".into())));
                assert!(map.contains_key(&Offset::Field("b".into())));
            }
            other => panic!("expected Obj, got {other:?}"),
        }
    }

    #[test]
    fn merge_into_obj_recurses_on_shared_keys() {
        // target = Obj{ a: Obj{ x: Tainted } }
        // source = Obj{ a: Obj{ y: Tainted } }
        // result = Obj{ a: Obj{ x: Tainted, y: Tainted } }
        let mut target = obj(vec![(
            Offset::Field("a".into()),
            obj(vec![(
                Offset::Field("x".into()),
                Cell::tainted(vec![TaintLabel::UserInput]),
            )]),
        )]);
        let source = obj(vec![(
            Offset::Field("a".into()),
            obj(vec![(
                Offset::Field("y".into()),
                Cell::tainted(vec![TaintLabel::UserInput]),
            )]),
        )]);
        target.merge_into(&source);
        // Drill into the nested Obj.
        let nested = match &target.shape {
            Shape::Obj(map) => map.get(&Offset::Field("a".into())).expect("a"),
            _ => panic!("expected Obj"),
        };
        match &nested.shape {
            Shape::Obj(inner) => {
                assert!(inner.contains_key(&Offset::Field("x".into())));
                assert!(inner.contains_key(&Offset::Field("y".into())));
            }
            other => panic!("expected nested Obj, got {other:?}"),
        }
    }

    #[test]
    fn merge_into_bot_is_identity() {
        // Merging Bot into anything is a no-op on the shape side.
        let original = obj(vec![(
            Offset::Field("a".into()),
            Cell::tainted(vec![TaintLabel::UserInput]),
        )]);
        let mut target = original.clone();
        target.merge_into(&Cell::bot());
        assert_eq!(target.shape, original.shape);
    }

    // ── Arg placeholder tests (slice 2.3 of ADR 0006) ───────────────────

    fn arg_id(name: &str, idx: u32) -> ArgId {
        ArgId {
            fn_id: name.into(),
            idx,
        }
    }

    fn arg_cell(id: ArgId) -> Cell {
        Cell {
            xtaint: Xtaint::None,
            shape: Shape::Arg(id),
        }
    }

    #[test]
    fn arg_placeholder_serde_roundtrips() {
        let cell = arg_cell(arg_id("createUser", 0));
        let json = serde_json::to_string(&cell).unwrap();
        let back: Cell = serde_json::from_str(&json).unwrap();
        assert_eq!(cell, back);
    }

    #[test]
    fn canonicalize_preserves_none_arg_cell() {
        // Unlike `None+Bot`, `None+Arg` carries the placeholder
        // identity and must survive canonicalize. Slice 2.3b will
        // instantiate this at call sites; until then it must stick
        // around in summaries.
        let cell = arg_cell(arg_id("pickField", 0));
        assert_eq!(cell.clone().canonicalize(), Some(cell));
    }

    #[test]
    fn canonicalize_clean_still_flattens_arg() {
        // Invariant 2: Clean shadows everything, including Arg.
        let cell = Cell {
            xtaint: Xtaint::Clean,
            shape: Shape::Arg(arg_id("anywhere", 1)),
        };
        let canonical = cell.canonicalize().expect("not dropped");
        assert_eq!(canonical.shape, Shape::Bot);
    }

    #[test]
    fn merge_into_obj_beats_arg() {
        // Concrete sub-structure beats opaque placeholder.
        let mut target = arg_cell(arg_id("f", 0));
        let source = obj(vec![(
            Offset::Field("a".into()),
            Cell::tainted(vec![TaintLabel::UserInput]),
        )]);
        target.merge_into(&source);
        assert!(matches!(target.shape, Shape::Obj(_)));
    }

    #[test]
    fn merge_into_arg_beats_bot() {
        let mut target = Cell::bot();
        let id = arg_id("f", 0);
        target.merge_into(&arg_cell(id.clone()));
        assert_eq!(target.shape, Shape::Arg(id));
    }

    #[test]
    fn merge_into_same_arg_id_is_idempotent() {
        let id = arg_id("pickField", 0);
        let mut target = arg_cell(id.clone());
        target.merge_into(&arg_cell(id.clone()));
        assert_eq!(target.shape, Shape::Arg(id));
    }

    #[test]
    fn merge_into_different_arg_ids_drops_to_bot() {
        // We don't have a representation for two different
        // polymorphic placeholders — conservatively drop.
        let mut target = arg_cell(arg_id("f", 0));
        target.merge_into(&arg_cell(arg_id("g", 0)));
        assert_eq!(target.shape, Shape::Bot);
    }

    #[test]
    fn merge_into_obj_target_keeps_obj_when_source_is_arg() {
        // Concrete target wins over opaque source.
        let mut target = obj(vec![(
            Offset::Field("a".into()),
            Cell::tainted(vec![TaintLabel::UserInput]),
        )]);
        target.merge_into(&arg_cell(arg_id("f", 0)));
        assert!(matches!(target.shape, Shape::Obj(_)));
    }

    // ── instantiate_tainted tests (slice 3.4 of ADR 0007) ───────────────

    #[test]
    fn instantiate_tainted_replaces_leaf_with_replacement() {
        // Single Tainted+Bot cell — replaced wholesale.
        let mut cell = Cell::tainted(vec![TaintLabel::UserInput]);
        let replacement = Cell::clean();
        cell.instantiate_tainted(&replacement);
        assert_eq!(cell, replacement);
    }

    #[test]
    fn instantiate_tainted_recurses_into_obj() {
        // Obj{a: Tainted, b: Tainted} — both leaves get the
        // replacement.
        let mut cell = obj(vec![
            (
                Offset::Field("a".into()),
                Cell::tainted(vec![TaintLabel::UserInput]),
            ),
            (
                Offset::Field("b".into()),
                Cell::tainted(vec![TaintLabel::UserInput]),
            ),
        ]);
        let replacement = arg_cell(arg_id("caller_param", 0));
        cell.instantiate_tainted(&replacement);
        match &cell.shape {
            Shape::Obj(map) => {
                let a = map.get(&Offset::Field("a".into())).unwrap();
                let b = map.get(&Offset::Field("b".into())).unwrap();
                assert!(matches!(a.shape, Shape::Arg(_)));
                assert!(matches!(b.shape, Shape::Arg(_)));
            }
            other => panic!("expected Obj, got {other:?}"),
        }
    }

    #[test]
    fn instantiate_tainted_leaves_non_tainted_cells_alone() {
        // None+Obj structure with no Tainted leaves stays unchanged.
        let cell = obj(vec![(Offset::Field("a".into()), Cell::clean())]);
        let mut copy = cell.clone();
        copy.instantiate_tainted(&Cell::tainted(vec![TaintLabel::UserInput]));
        assert_eq!(copy, cell);
    }

    #[test]
    fn instantiate_tainted_preserves_substructure_under_tainted() {
        // Tainted cell with Obj sub-structure — the replacement
        // merges with the existing sub-structure rather than
        // discarding it. This matters because a return shape can
        // carry both "this cell is tainted" AND "we know its .x
        // sub-cell"; instantiation should preserve both.
        let mut cell = Cell {
            xtaint: Xtaint::Tainted(vec![TaintLabel::UserInput]),
            shape: Shape::Obj({
                let mut m = std::collections::BTreeMap::new();
                m.insert(Offset::Field("known".into()), Cell::clean());
                m
            }),
        };
        let replacement = obj(vec![(
            Offset::Field("from_caller".into()),
            Cell::tainted(vec![TaintLabel::UserInput]),
        )]);
        cell.instantiate_tainted(&replacement);
        // Result: an Obj with both `known` (from original) and
        // `from_caller` (from replacement). The xtaint of the cell
        // is the replacement's (None, since replacement was None+Obj).
        assert_eq!(cell.xtaint, Xtaint::None);
        match &cell.shape {
            Shape::Obj(map) => {
                assert!(map.contains_key(&Offset::Field("known".into())));
                assert!(map.contains_key(&Offset::Field("from_caller".into())));
            }
            other => panic!("expected merged Obj, got {other:?}"),
        }
    }

    // ── strip_arg_for tests (slice 2.3b of ADR 0006) ────────────────────

    #[test]
    fn strip_arg_for_replaces_matching_arg_with_bot() {
        let mut cell = arg_cell(arg_id("helper", 0));
        cell.strip_arg_for("helper");
        assert_eq!(cell.shape, Shape::Bot);
    }

    #[test]
    fn strip_arg_for_leaves_non_matching_arg_alone() {
        let mut cell = arg_cell(arg_id("helper", 0));
        cell.strip_arg_for("other_fn");
        assert!(matches!(cell.shape, Shape::Arg(_)));
    }

    #[test]
    fn strip_arg_for_recurses_into_obj_map() {
        // Outer Obj contains an inner Arg cell. After strip_arg_for,
        // the inner Arg is Bot but the outer Obj structure is intact.
        let mut cell = obj(vec![
            (
                Offset::Field("a".into()),
                Cell::tainted(vec![TaintLabel::UserInput]),
            ),
            (Offset::Field("b".into()), arg_cell(arg_id("helper", 0))),
        ]);
        cell.strip_arg_for("helper");
        match &cell.shape {
            Shape::Obj(map) => {
                let b = map.get(&Offset::Field("b".into())).unwrap();
                assert_eq!(b.shape, Shape::Bot);
                // The Tainted entry under `a` is unchanged.
                let a = map.get(&Offset::Field("a".into())).unwrap();
                assert!(matches!(a.xtaint, Xtaint::Tainted(_)));
            }
            other => panic!("expected Obj, got {other:?}"),
        }
    }

    #[test]
    fn strip_arg_for_does_not_touch_bot_or_tainted_leaves() {
        // Strip should be a no-op when the cell carries no Arg.
        let mut cell = obj(vec![(
            Offset::Field("a".into()),
            Cell::tainted(vec![TaintLabel::UserInput]),
        )]);
        let original = cell.clone();
        cell.strip_arg_for("anywhere");
        assert_eq!(cell, original);
    }

    // ── derivation methods (slice 2.5 of ADR 0006) ──────────────────────

    #[test]
    fn has_tainted_leaf_matches_count_predicate() {
        // Bare-bot, Arg, and Clean cells have no tainted leaves.
        assert!(!Cell::bot().has_tainted_leaf());
        assert!(!arg_cell(arg_id("f", 0)).has_tainted_leaf());
        assert!(!Cell::clean().has_tainted_leaf());
        // Tainted-rooted is a leaf.
        assert!(Cell::tainted(vec![TaintLabel::UserInput]).has_tainted_leaf());
        // Nested: tainted under an Obj is also a leaf.
        let nested = obj(vec![(
            Offset::Field("a".into()),
            Cell::tainted(vec![TaintLabel::UserInput]),
        )]);
        assert!(nested.has_tainted_leaf());
    }

    #[test]
    fn top_tainted_offsets_includes_only_tainted_subtrees() {
        // Mix of useful and useless top-level entries — only the
        // ones with Tainted descendants are included.
        let cell = obj(vec![
            (
                Offset::Field("dirty".into()),
                Cell::tainted(vec![TaintLabel::UserInput]),
            ),
            (Offset::Field("clean".into()), Cell::clean()),
        ]);
        let offsets = cell.top_tainted_offsets();
        assert_eq!(offsets, vec![Offset::Field("dirty".into())]);
    }

    #[test]
    fn top_tainted_offsets_walks_nested_obj_to_find_taint() {
        // body.where.id is tainted — top-level offset is `where`,
        // because its sub-tree contains a Tainted leaf.
        let cell = obj(vec![(
            Offset::Field("where".into()),
            obj(vec![(
                Offset::Field("id".into()),
                Cell::tainted(vec![TaintLabel::UserInput]),
            )]),
        )]);
        assert_eq!(
            cell.top_tainted_offsets(),
            vec![Offset::Field("where".into())]
        );
    }

    #[test]
    fn top_tainted_offsets_empty_for_whole_value_taint() {
        // Tainted+Bot — no top-level structural keys, so no offsets.
        // Phase 1's slice-2 contract: bare-ident pass-through records
        // an empty `tainted_offsets`, signalled via the boolean alone.
        let cell = Cell::tainted(vec![TaintLabel::UserInput]);
        assert!(cell.top_tainted_offsets().is_empty());
    }

    #[test]
    fn top_tainted_offsets_empty_for_arg_placeholder() {
        let cell = arg_cell(arg_id("helper", 0));
        assert!(cell.top_tainted_offsets().is_empty());
    }

    #[test]
    fn arg_contributes_no_tainted_leaves() {
        // A placeholder by itself is not tainted; it only becomes
        // tainted after instantiation. count_tainted_leaves must
        // return 0 for `None+Arg`.
        let cell = arg_cell(arg_id("f", 0));
        assert_eq!(cell.count_tainted_leaves(), 0);
        // But a Tainted+Arg would count its own xtaint:
        let tainted_arg = Cell {
            xtaint: Xtaint::Tainted(vec![TaintLabel::UserInput]),
            shape: Shape::Arg(arg_id("f", 0)),
        };
        assert_eq!(tainted_arg.count_tainted_leaves(), 1);
    }

    #[test]
    fn canonicalize_is_idempotent() {
        // canonicalize(canonicalize(c)) == canonicalize(c) for a
        // representative non-trivial shape.
        let mut inner = std::collections::BTreeMap::new();
        inner.insert(
            Offset::Field("nested".into()),
            Cell::tainted(vec![
                TaintLabel::Secret,
                TaintLabel::UserInput,
                TaintLabel::Secret, // dupe to force normalization
            ]),
        );
        inner.insert(Offset::Field("dead".into()), Cell::bot());
        let c = Cell {
            xtaint: Xtaint::None,
            shape: Shape::Obj({
                let mut outer = std::collections::BTreeMap::new();
                outer.insert(
                    Offset::Field("a".into()),
                    Cell {
                        xtaint: Xtaint::None,
                        shape: Shape::Obj(inner),
                    },
                );
                outer.insert(Offset::Field("z".into()), Cell::clean());
                outer
            }),
        };
        let once = c.canonicalize().expect("not dropped");
        let twice = once.clone().canonicalize().expect("not dropped");
        assert_eq!(once, twice, "canonicalize must be idempotent");
    }
}
