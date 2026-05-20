//! `data/pg` adapter — node-postgres raw-query sink surface.
//!
//! `pg` (a.k.a. node-postgres) is the standard low-level Postgres
//! client for Node.js. Unlike Prisma or Drizzle, it has no ORM
//! abstraction: code constructs SQL strings directly and hands them
//! to `pool.query(...)` or `client.query(...)`. That makes every
//! `query(...)` call site a potential `flow/sql-injection` sink when
//! the first argument is concatenated with untrusted input rather
//! than passed as the parameterised `(text, [bind])` form.
//!
//! The idiomatic shapes are:
//!
//! ```text
//! pool.query('SELECT * FROM users WHERE id = ' + req.params.id)  // BAD
//! pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]) // OK
//! client.query(sqlStringWithInterpolatedBody)                    // BAD
//! ```
//!
//! ## Sinks
//!
//! Raw-SQL escape hatches (`SinkKind::RawSql`, `Severity::Critical`
//! floor) — `pg` has no ORM-style write helpers, so every `query(...)`
//! call is a candidate raw-SQL sink. The first argument is the SQL
//! text; the downstream `flow/sql-injection` rule inspects it for
//! `UserInput` taint and ignores calls where the text is a static
//! literal followed by a bind array.
//!
//! Receivers are matched by a closed set of conventional names —
//! `pool`, `client`, `db`, `connection` — via [`AstMatcher::MethodCall`].
//! These mirror the inline recogniser in
//! [`crate::steps::sinks::sql::is_sql_sink_call`] so adapter and inline
//! paths are shape-equivalent during rule migration.
//!
//! ### Trade-off: literal receiver match
//!
//! [`AstMatcher::MethodCall`] requires a *literal* receiver-identifier
//! match. Real-world `pg` codebases occasionally name their pool /
//! client binding off the schema or context (e.g. `userDb.query(...)`,
//! `appPool.query(...)`, `readReplica.query(...)`). Those receivers
//! fall outside the closed set in this adapter and the inline
//! [`crate::steps::sinks::sql::is_sql_sink_call`] recogniser — neither
//! path fires.
//!
//! This matches the inline behaviour exactly: the conventional-name
//! list was deliberate there too, to avoid false positives on every
//! `.query(...)` method in the codebase (e.g. URL query helpers,
//! ElasticSearch clients, generic query builders). The adapter
//! inherits that trade-off rather than widening it: when rules
//! migrate to consume the substrate, the matcher set can be extended
//! (e.g. an `MethodCallAnyReceiver { method: "query" }` gated by an
//! adapter-level `pg`-import propagation pass) or the rule can fall
//! back to inline heuristics for the unconventional-receiver gap. For
//! v0.4.0 the inline path still wins for receivers outside this set.
//!
//! ## Sources, sanitisers, guards
//!
//! None. `pg` is a sink-only surface — it doesn't introduce taint
//! and has no built-in sanitisation. Parameterised queries are
//! recognised by the downstream rule based on the second-argument
//! bind array, not by an adapter pattern.
//!
//! ## Activation
//!
//! Default `is_enabled` — active when the project profile contains a
//! [`DataLayerHint::Pg`] entry at confidence ≥
//! [`ENABLE_CONFIDENCE_FLOOR`] (`0.60`). The profile crate serialises
//! `Pg` as `"pg"`, which matches the `pg` suffix in this adapter's
//! `data/pg` ID.
//!
//! [`DataLayerHint::Pg`]: stryx_index::profile::DataLayerHint::Pg
//! [`ENABLE_CONFIDENCE_FLOOR`]: crate::adapters::ENABLE_CONFIDENCE_FLOOR

use crate::adapters::{AdapterId, AdapterKind, AstMatcher, SinkKind, SinkPattern, StackAdapter};
use stryx_core::Severity;

pub struct PgAdapter;

static SINKS: &[SinkPattern] = &[
    // ── Raw-SQL escape hatches: <conn>.query(<sql>, ...) ─────────────
    //
    // One pattern per conventional receiver name. Splitting per-receiver
    // (rather than one pattern with multiple matchers) keeps each ID
    // attributable in reporter output — a finding on `pool.query(...)`
    // reads `data/pg/pool-query`, distinguishing pool vs single-client
    // call sites for operators reviewing diagnostics.
    SinkPattern {
        id: "data/pg/pool-query",
        sink: SinkKind::RawSql,
        matchers: &[AstMatcher::MethodCall {
            receiver: "pool",
            method: "query",
        }],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "data/pg/client-query",
        sink: SinkKind::RawSql,
        matchers: &[AstMatcher::MethodCall {
            receiver: "client",
            method: "query",
        }],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "data/pg/db-query",
        sink: SinkKind::RawSql,
        matchers: &[AstMatcher::MethodCall {
            receiver: "db",
            method: "query",
        }],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "data/pg/connection-query",
        sink: SinkKind::RawSql,
        matchers: &[AstMatcher::MethodCall {
            receiver: "connection",
            method: "query",
        }],
        severity_floor: Severity::Critical,
    },
];

impl StackAdapter for PgAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("data/pg")
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
    fn pg_adapter_exposes_expected_sink_patterns() {
        // One sink per conventional `pg` receiver name. The set mirrors
        // the inline `is_sql_sink_call` recogniser in
        // `crate::steps::sinks::sql` so the adapter and inline paths
        // are shape-equivalent.
        let sinks = PgAdapter.sinks();
        assert_eq!(sinks.len(), 4);
        let ids: Vec<&str> = sinks.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"data/pg/pool-query"));
        assert!(ids.contains(&"data/pg/client-query"));
        assert!(ids.contains(&"data/pg/db-query"));
        assert!(ids.contains(&"data/pg/connection-query"));
    }

    #[test]
    fn pg_adapter_is_data_layer_kind() {
        assert_eq!(PgAdapter.kind(), AdapterKind::DataLayer);
        assert_eq!(PgAdapter.id(), AdapterId("data/pg"));
    }

    #[test]
    fn pg_sinks_floor_at_critical() {
        // Every `pg` sink is a raw-SQL escape hatch — SQL injection
        // here is OWASP A03:2021 / CWE-89, so the floor is `Critical`.
        // There are no `DbWrite` sinks on `pg` (it's a sink-only,
        // ORM-less surface), so the check is uniform.
        for sink in PgAdapter.sinks() {
            assert!(
                matches!(sink.sink, SinkKind::RawSql),
                "pg sink {} should be RawSql",
                sink.id
            );
            assert_eq!(
                sink.severity_floor,
                Severity::Critical,
                "raw-SQL sink {} should floor at Critical",
                sink.id
            );
        }
    }

    #[test]
    fn is_enabled_returns_true_under_pg_profile() {
        // High-confidence `pg` detection in the profile must activate
        // the adapter via the default `is_enabled` path (matches
        // `data/<name>` adapter ID suffix against the
        // `DataLayerHint::Pg` serde spelling `"pg"`).
        let profile = ProjectProfile {
            data_layers: vec![Detected {
                id: DataLayerHint::Pg,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(PgAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_mysql2_profile() {
        // A mysql2-only profile must not activate the `pg` adapter,
        // even at high confidence — adapter activation is per-name,
        // not per-kind. Both `Pg` and `Mysql2` are `DataLayerHint`
        // variants, but only the matching name wires through
        // `is_enabled_default`. The mysql2 adapter (when it ships)
        // will mirror the same receiver shape under its own ID.
        let profile = ProjectProfile {
            data_layers: vec![Detected {
                id: DataLayerHint::Mysql2,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!PgAdapter.is_enabled(&profile));
    }
}
