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

/// A taint shape — Semgrep's `shape` from `Shape_and_sig.ml`. A shape
/// approximates the *structure* of a value being tracked, with each
/// reachable cell carrying its own [`Xtaint`].
///
/// Slice 2.1a ships only [`Shape::Bot`] and [`Shape::Obj`]. The
/// polymorphic-parameter constructor (`Arg`) lands in slice 2.3 and
/// the higher-order-function constructor (`Fun`) in slice 2.4.
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
/// 1. If `xtaint == Xtaint::None`, then `shape != Shape::Bot` and
///    the shape transitively reaches a `Tainted`/`Clean` cell.
///    Otherwise the cell carries no information and should be
///    omitted from its parent map.
/// 2. If `xtaint == Xtaint::Clean`, then `shape == Shape::Bot`.
///    Cleanness shadows sub-structure; any `Obj` content under a
///    `Clean` cell is meaningless.
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
        // Shape join.
        match (&source.shape, &mut self.shape) {
            (Shape::Bot, _) => { /* nothing to add */ }
            (src @ Shape::Obj(_), Shape::Bot) => {
                self.shape = src.clone();
            }
            (Shape::Obj(s_map), Shape::Obj(t_map)) => {
                for (off, s_cell) in s_map {
                    let t_cell = t_map.entry(off.clone()).or_insert_with(Cell::bot);
                    t_cell.merge_into(s_cell);
                }
            }
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
        // Invariant 1: None + Bot is meaningless — drop.
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
/// collapses to `Bot`.
fn canonicalize_shape(shape: Shape) -> Shape {
    match shape {
        Shape::Bot => Shape::Bot,
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
