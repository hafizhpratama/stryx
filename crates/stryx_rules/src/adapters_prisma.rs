//! `data/prisma` adapter — Prisma Client write surface and raw-SQL
//! escape hatches.
//!
//! Prisma is the most widely deployed TypeScript ORM. Its idiomatic
//! call shape is `prisma.<model>.<method>(args)` — the model segment is
//! schema-derived and varies per project, so this adapter recognises
//! sinks by *method name* via [`AstMatcher::MethodCallAnyReceiver`].
//! That matches the inline `is_prisma_write_sink` recogniser in
//! [`crate::steps::sinks::db`] for the method-name dimension; the
//! receiver-shape constraint (chain rooted at `prisma`/`db`/`database`)
//! stays in that inline predicate during the rule-migration slice and
//! is intentionally *not* mirrored here. Once rules consume
//! `ctx.match_sink`, the registry view widens to "any `<receiver>.create(...)`"
//! — wider than the inline predicate by design, because most real-world
//! Prisma client bindings are named off the schema convention (`db`,
//! `prisma`, `database`, occasionally branded names like `appDb`).
//! Adapter activation gates the registry view: this widening only
//! applies under a confirmed `data/prisma` profile.
//!
//! ## Sinks
//!
//! DB writes (`SinkKind::DbWrite`, `Severity::High` floor) — each is
//! a Prisma Client mutation entry point that consumes a `data:` /
//! `where:` object likely sourced from request input:
//!
//! - `create`, `createMany` — INSERT
//! - `update`, `updateMany`, `upsert` — UPDATE (+ optional INSERT)
//! - `delete`, `deleteMany` — DELETE
//!
//! These reach `flow/unvalidated-body-to-db`. The downstream rule may
//! downgrade `delete`/`deleteMany` to Medium when only the `where`
//! clause is tainted (the existing severity-rule path in
//! `flows/unvalidated_body_to_db.rs`); the adapter's `severity_floor`
//! is the rule's *minimum*, not its assigned severity, so the rule can
//! lower its assignment for the specific where-only case without
//! conflicting with the floor.
//!
//! Raw-SQL escape hatches (`SinkKind::RawSql`, `Severity::Critical`
//! floor) — by-name only, because these methods are unique to Prisma
//! Client and are dangerous on any receiver:
//!
//! - `$queryRawUnsafe`, `$executeRawUnsafe`
//!
//! These reach `flow/sql-injection`. The tagged-template variants
//! `$queryRaw\`...\`` and `$executeRaw\`...\`` are parameterised by
//! construction and are intentionally **not** sinks here — they are
//! safe by design and would never match `MethodCallAnyReceiver` against
//! a call-expression in any case (tagged templates are
//! `TaggedTemplateExpression`, not `CallExpression`).
//!
//! ## Sources
//!
//! None. Data-layer adapters are sink consumers, not source producers.
//!
//! ## Activation
//!
//! Default `is_enabled` — active when the project profile contains a
//! `DataLayerHint::Prisma` entry at confidence ≥
//! [`ENABLE_CONFIDENCE_FLOOR`] (`0.60`). The profile crate serialises
//! `Prisma` as `"prisma"`, which matches the `prisma` suffix in this
//! adapter's `data/prisma` ID.
//!
//! [`ENABLE_CONFIDENCE_FLOOR`]: crate::adapters::ENABLE_CONFIDENCE_FLOOR

use crate::adapters::{AdapterId, AdapterKind, AstMatcher, SinkKind, SinkPattern, StackAdapter};
use stryx_core::Severity;

pub struct PrismaAdapter;

static SINKS: &[SinkPattern] = &[
    // ── DB writes ────────────────────────────────────────────────────
    SinkPattern {
        id: "data/prisma/create",
        sink: SinkKind::DbWrite,
        matchers: &[AstMatcher::MethodCallAnyReceiver { method: "create" }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "data/prisma/create-many",
        sink: SinkKind::DbWrite,
        matchers: &[AstMatcher::MethodCallAnyReceiver {
            method: "createMany",
        }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "data/prisma/update",
        sink: SinkKind::DbWrite,
        matchers: &[AstMatcher::MethodCallAnyReceiver { method: "update" }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "data/prisma/update-many",
        sink: SinkKind::DbWrite,
        matchers: &[AstMatcher::MethodCallAnyReceiver {
            method: "updateMany",
        }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "data/prisma/upsert",
        sink: SinkKind::DbWrite,
        matchers: &[AstMatcher::MethodCallAnyReceiver { method: "upsert" }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "data/prisma/delete",
        sink: SinkKind::DbWrite,
        matchers: &[AstMatcher::MethodCallAnyReceiver { method: "delete" }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "data/prisma/delete-many",
        sink: SinkKind::DbWrite,
        matchers: &[AstMatcher::MethodCallAnyReceiver {
            method: "deleteMany",
        }],
        severity_floor: Severity::High,
    },
    // ── Raw-SQL escape hatches ───────────────────────────────────────
    SinkPattern {
        id: "data/prisma/queryrawunsafe",
        sink: SinkKind::RawSql,
        matchers: &[AstMatcher::MethodCallAnyReceiver {
            method: "$queryRawUnsafe",
        }],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "data/prisma/executerawunsafe",
        sink: SinkKind::RawSql,
        matchers: &[AstMatcher::MethodCallAnyReceiver {
            method: "$executeRawUnsafe",
        }],
        severity_floor: Severity::Critical,
    },
];

impl StackAdapter for PrismaAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("data/prisma")
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
    fn prisma_adapter_exposes_expected_sink_patterns() {
        let sinks = PrismaAdapter.sinks();
        assert_eq!(sinks.len(), 9);
        let ids: Vec<&str> = sinks.iter().map(|s| s.id).collect();
        // DB writes (7).
        assert!(ids.contains(&"data/prisma/create"));
        assert!(ids.contains(&"data/prisma/create-many"));
        assert!(ids.contains(&"data/prisma/update"));
        assert!(ids.contains(&"data/prisma/update-many"));
        assert!(ids.contains(&"data/prisma/upsert"));
        assert!(ids.contains(&"data/prisma/delete"));
        assert!(ids.contains(&"data/prisma/delete-many"));
        // Raw-SQL escapes (2).
        assert!(ids.contains(&"data/prisma/queryrawunsafe"));
        assert!(ids.contains(&"data/prisma/executerawunsafe"));
    }

    #[test]
    fn prisma_adapter_is_data_layer_kind() {
        assert_eq!(PrismaAdapter.kind(), AdapterKind::DataLayer);
        assert_eq!(PrismaAdapter.id(), AdapterId("data/prisma"));
    }

    #[test]
    fn prisma_db_writes_floor_at_high() {
        // Every DB-write sink must carry `SinkKind::DbWrite` with a
        // `Severity::High` floor — the downstream rule may downgrade
        // specific cases (e.g. where-only deletes) but the registry
        // floor is the rule's minimum, not its assigned severity.
        for sink in PrismaAdapter.sinks() {
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
    fn prisma_raw_sql_escapes_floor_at_critical() {
        // `$queryRawUnsafe` / `$executeRawUnsafe` are the un-
        // parameterised escape hatches — SQL injection here is OWASP
        // A03:2021 / CWE-89, so the floor is `Critical`.
        for sink in PrismaAdapter.sinks() {
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
    fn is_enabled_returns_true_under_prisma_profile() {
        // High-confidence Prisma detection in the profile must activate
        // the adapter via the default `is_enabled` path (matches
        // `data/<name>` adapter ID suffix against the
        // `DataLayerHint::Prisma` serde spelling `"prisma"`).
        let profile = ProjectProfile {
            data_layers: vec![Detected {
                id: DataLayerHint::Prisma,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(PrismaAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_drizzle_profile() {
        // A Drizzle-only profile must not activate the Prisma adapter,
        // even at high confidence — adapter activation is per-name,
        // not per-kind.
        let profile = ProjectProfile {
            data_layers: vec![Detected {
                id: DataLayerHint::Drizzle,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!PrismaAdapter.is_enabled(&profile));
    }
}
