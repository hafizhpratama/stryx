//! `data/drizzle` adapter — Drizzle ORM write surface and raw-SQL
//! escape hatches.
//!
//! Drizzle is the second most widely deployed TypeScript ORM. Its
//! idiomatic write call shape is a chained builder:
//!
//! ```text
//! db.insert(users).values({ name: req.body.name })
//! db.update(users).set({ name: req.body.name }).where(eq(users.id, id))
//! db.delete(users).where(eq(users.id, id))
//! ```
//!
//! The interesting taint surface lives on *both* the chain-root call
//! (`db.insert(table)`, `db.update(table)`, `db.delete(table)`) and the
//! terminal data argument (`.values(arg)`, `.set(arg)`). Either is a
//! `flow/unvalidated-body-to-db` trigger when the relevant argument
//! carries `UserInput` taint: the chain-root call's argument is the
//! target *table* identifier (usually a static schema import, not
//! tainted) but recognising it as a sink lets the rule attribute the
//! finding to the correct call site; the terminal `.values` / `.set`
//! call's argument is the object literal that actually carries body
//! data.
//!
//! All five method-name shapes are matched by [`AstMatcher::MethodCallAnyReceiver`].
//! That widens beyond the inline predicate in [`crate::steps::sinks::db`]
//! (which constrains the chain root to one of `db` / `prisma` / etc.)
//! — deliberately, mirroring the [`crate::adapters_prisma`] design: the
//! widening only activates under a confirmed `data/drizzle` profile, so
//! real-world Drizzle bindings under any name (`db`, `database`,
//! `appDb`, branded names) are still recognised without expanding the
//! generic recogniser's hardcoded receiver list.
//!
//! ## Sinks
//!
//! DB writes (`SinkKind::DbWrite`, `Severity::High` floor) — each is a
//! Drizzle builder entry point or terminal-data setter that consumes a
//! `data` / `set` object likely sourced from request input:
//!
//! - `insert` — chain-root for `db.insert(table)`
//! - `update` — chain-root for `db.update(table)`
//! - `delete` — chain-root for `db.delete(table)`
//! - `values` — terminal data setter, chained after `insert`
//! - `set` — terminal data setter, chained after `update`
//!
//! These reach `flow/unvalidated-body-to-db`. As with the Prisma
//! adapter, the downstream rule may downgrade where-only flows; the
//! `severity_floor` is the rule's *minimum*, not its assigned severity.
//!
//! Raw-SQL escape hatches (`SinkKind::RawSql`, `Severity::Critical`
//! floor) — Drizzle exposes two interchangeable un-parameterised
//! entry points, both reachable via the `sql` import from
//! `drizzle-orm`:
//!
//! - `sql.raw(...)` — receiver-pinned to the `sql` identifier (the
//!   only receiver Drizzle ships this method on), matched via
//!   [`AstMatcher::MethodCall`]
//! - `sql(...)` called as a function (not a tagged template) — matched
//!   via [`AstMatcher::ImportedCall`] against the `drizzle-orm` import,
//!   which distinguishes a real Drizzle `sql(...)` call from any local
//!   identifier that happens to be named `sql`
//!
//! These reach `flow/sql-injection`.
//!
//! **The tagged-template form `` sql`SELECT ...` `` is parameterised
//! by construction** — Drizzle splits the template literal's static
//! parts from its dynamic placeholders and binds the latter as
//! parameters. That form is safe by design and **must not** fire.
//! All three matchers above key off `CallExpression`; tagged templates
//! are `TaggedTemplateExpression`, a distinct AST node, so the
//! discrimination is implicit and free.
//!
//! ## Sources
//!
//! None. Data-layer adapters are sink consumers, not source producers.
//!
//! ## Activation
//!
//! Default `is_enabled` — active when the project profile contains a
//! `DataLayerHint::Drizzle` entry at confidence ≥
//! [`ENABLE_CONFIDENCE_FLOOR`] (`0.60`). The profile crate serialises
//! `Drizzle` as `"drizzle"`, which matches the `drizzle` suffix in this
//! adapter's `data/drizzle` ID.
//!
//! [`ENABLE_CONFIDENCE_FLOOR`]: crate::adapters::ENABLE_CONFIDENCE_FLOOR

use crate::adapters::{AdapterId, AdapterKind, AstMatcher, SinkKind, SinkPattern, StackAdapter};
use stryx_core::Severity;

pub struct DrizzleAdapter;

static SINKS: &[SinkPattern] = &[
    // ── DB writes — chain-root builders ──────────────────────────────
    SinkPattern {
        id: "data/drizzle/insert",
        sink: SinkKind::DbWrite,
        matchers: &[AstMatcher::MethodCallAnyReceiver { method: "insert" }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "data/drizzle/update",
        sink: SinkKind::DbWrite,
        matchers: &[AstMatcher::MethodCallAnyReceiver { method: "update" }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "data/drizzle/delete",
        sink: SinkKind::DbWrite,
        matchers: &[AstMatcher::MethodCallAnyReceiver { method: "delete" }],
        severity_floor: Severity::High,
    },
    // ── DB writes — terminal data setters ────────────────────────────
    SinkPattern {
        id: "data/drizzle/values",
        sink: SinkKind::DbWrite,
        matchers: &[AstMatcher::MethodCallAnyReceiver { method: "values" }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "data/drizzle/set",
        sink: SinkKind::DbWrite,
        matchers: &[AstMatcher::MethodCallAnyReceiver { method: "set" }],
        severity_floor: Severity::High,
    },
    // ── Raw-SQL escape hatches ───────────────────────────────────────
    SinkPattern {
        id: "data/drizzle/sql-raw",
        sink: SinkKind::RawSql,
        // Receiver-pinned: `sql.raw(...)` only. `MethodCall` requires
        // the literal `sql` identifier as receiver, ruling out any
        // unrelated `.raw()` method on other objects.
        matchers: &[AstMatcher::MethodCall {
            receiver: "sql",
            method: "raw",
        }],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "data/drizzle/sql-tagged-call",
        sink: SinkKind::RawSql,
        // `sql(...)` invoked as a bare call (not tagged) from the
        // `drizzle-orm` import. `ImportedCall` consults the file's
        // import map so a local function literally named `sql` does
        // not match. Tagged-template form `sql`...`` is a
        // TaggedTemplateExpression, not a CallExpression, and is
        // intentionally not matched — Drizzle parameterises it.
        matchers: &[AstMatcher::ImportedCall {
            module: "drizzle-orm",
            name: "sql",
        }],
        severity_floor: Severity::Critical,
    },
];

impl StackAdapter for DrizzleAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("data/drizzle")
    }
    fn kind(&self) -> AdapterKind {
        AdapterKind::DataLayer
    }
    fn sinks(&self) -> &'static [SinkPattern] {
        SINKS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stryx_index::profile::{DataLayerHint, Detected, ProjectProfile};

    #[test]
    fn drizzle_adapter_exposes_expected_sink_patterns() {
        let sinks = DrizzleAdapter.sinks();
        assert_eq!(sinks.len(), 7);
        let ids: Vec<&str> = sinks.iter().map(|s| s.id).collect();
        // DB-write chain roots (3).
        assert!(ids.contains(&"data/drizzle/insert"));
        assert!(ids.contains(&"data/drizzle/update"));
        assert!(ids.contains(&"data/drizzle/delete"));
        // DB-write terminal data setters (2).
        assert!(ids.contains(&"data/drizzle/values"));
        assert!(ids.contains(&"data/drizzle/set"));
        // Raw-SQL escape hatches (2).
        assert!(ids.contains(&"data/drizzle/sql-raw"));
        assert!(ids.contains(&"data/drizzle/sql-tagged-call"));
    }

    #[test]
    fn drizzle_adapter_is_data_layer_kind() {
        assert_eq!(DrizzleAdapter.kind(), AdapterKind::DataLayer);
        assert_eq!(DrizzleAdapter.id(), AdapterId("data/drizzle"));
    }

    #[test]
    fn drizzle_db_writes_floor_at_high() {
        // Every DB-write sink — chain-root and terminal setter alike —
        // must carry `SinkKind::DbWrite` with a `Severity::High` floor.
        // The downstream `flow/unvalidated-body-to-db` rule may
        // downgrade specific cases (e.g. delete-by-id), but the
        // registry floor is the rule's minimum, not its assigned
        // severity.
        for sink in DrizzleAdapter.sinks() {
            if matches!(sink.sink, SinkKind::DbWrite) {
                assert_eq!(
                    sink.severity_floor,
                    Severity::High,
                    "DB-write sink {} should floor at High",
                    sink.id
                );
            }
        }
    }

    #[test]
    fn drizzle_raw_sql_floor_at_critical() {
        // `sql.raw(...)` and the bare-call `sql(...)` form are the un-
        // parameterised escape hatches — SQL injection here is OWASP
        // A03:2021 / CWE-89, so the floor is `Critical`. The
        // tagged-template form is parameterised by construction and
        // is intentionally not represented as a sink at all (see
        // module docs).
        for sink in DrizzleAdapter.sinks() {
            if matches!(sink.sink, SinkKind::RawSql) {
                assert_eq!(
                    sink.severity_floor,
                    Severity::Critical,
                    "raw-SQL sink {} should floor at Critical",
                    sink.id
                );
            }
        }
    }

    #[test]
    fn is_enabled_returns_true_under_drizzle_profile() {
        // High-confidence Drizzle detection in the profile must
        // activate the adapter via the default `is_enabled` path
        // (matches `data/<name>` adapter ID suffix against the
        // `DataLayerHint::Drizzle` serde spelling `"drizzle"`).
        let profile = ProjectProfile {
            data_layers: vec![Detected {
                id: DataLayerHint::Drizzle,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(DrizzleAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_prisma_profile() {
        // A Prisma-only profile must not activate the Drizzle adapter,
        // even at high confidence — adapter activation is per-name,
        // not per-kind. Mirrors `is_enabled_returns_false_under_drizzle_profile`
        // in the Prisma adapter; together they pin the symmetric
        // exclusion between the two data-layer adapters.
        let profile = ProjectProfile {
            data_layers: vec![Detected {
                id: DataLayerHint::Prisma,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!DrizzleAdapter.is_enabled(&profile));
    }
}
