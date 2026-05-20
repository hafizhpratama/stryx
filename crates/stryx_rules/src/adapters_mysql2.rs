//! `data/mysql2` adapter — mysql2 raw-query and prepared-statement
//! sink surface.
//!
//! [`mysql2`] is the standard low-level MySQL client for Node.js.
//! Like [`pg`], it has no ORM abstraction: code constructs SQL
//! strings directly and hands them to either `<conn>.query(...)`
//! (the immediate-execution path) or `<conn>.execute(...)` (the
//! prepared-statement path). That makes every call site on either
//! method a potential `flow/sql-injection` sink when the first
//! argument is concatenated with untrusted input rather than passed
//! as the parameterised `(text, [bind])` form.
//!
//! [`mysql2`]: https://github.com/sidorares/node-mysql2
//! [`pg`]: crate::adapters_pg
//!
//! The idiomatic shapes are:
//!
//! ```text
//! pool.query('SELECT * FROM users WHERE id = ' + req.params.id)   // BAD
//! pool.query('SELECT * FROM users WHERE id = ?', [req.params.id]) // OK
//! pool.execute('SELECT * FROM users WHERE id = ?', [id])          // OK (prepared)
//! pool.execute('SELECT * FROM users WHERE id = ' + id)            // BAD (still concat)
//! connection.execute(stringWithInterpolatedBody)                  // BAD
//! ```
//!
//! ## Sinks
//!
//! Raw-SQL escape hatches (`SinkKind::RawSql`, `Severity::Critical`
//! floor) — every `<conn>.query(...)` and `<conn>.execute(...)` call
//! is a candidate raw-SQL sink. The first argument is the SQL text;
//! the downstream `flow/sql-injection` rule inspects it for
//! `UserInput` taint and ignores calls where the text is a static
//! literal followed by a bind array.
//!
//! Receivers are matched by a closed set of conventional names —
//! `pool`, `client`, `db`, `connection` — via [`AstMatcher::MethodCall`],
//! mirroring the [`crate::adapters_pg`] approach so the two
//! low-level SQL clients have identical receiver coverage.
//!
//! ### Trade-off 1: `.execute` is the prepared-statement API
//!
//! mysql2's `.execute(text, params)` is the *parameterised*
//! statement API — when the SQL text is a static literal with `?`
//! placeholders and the params arrive in the bind array, the client
//! sends them over the binary protocol and SQL injection is
//! prevented at the driver layer. Treating every `.execute(...)`
//! call as a sink looks over-eager at first glance.
//!
//! It isn't. The driver only protects bind parameters — the SQL
//! text itself is sent verbatim. Code that builds the text by
//! concatenating user input (`pool.execute('SELECT ' + col +
//! ' FROM users WHERE id = ?', [id])`) is still injectable through
//! the concatenated portion, and that exact pattern is common when
//! callers reach for `.execute` thinking it makes everything safe.
//! The downstream `flow/sql-injection` rule inspects the *first
//! argument* for `UserInput` taint, so static-literal-only
//! `.execute` calls produce no finding while concatenated ones do.
//!
//! ### Trade-off 2: literal receiver match (closed set)
//!
//! [`AstMatcher::MethodCall`] requires a *literal* receiver-identifier
//! match. Real-world mysql2 codebases occasionally name their
//! pool / connection binding off the schema or context (e.g.
//! `userDb.query(...)`, `appPool.execute(...)`, `readReplica.query(...)`).
//! Those receivers fall outside the closed set in this adapter and
//! the inline [`crate::steps::sinks::sql::is_sql_sink_call`]
//! recogniser — neither path fires.
//!
//! This matches the inline behaviour exactly: the conventional-name
//! list was deliberate there too, to avoid false positives on every
//! `.query(...)` and `.execute(...)` method in the codebase (e.g.
//! URL query helpers, generic command runners, batch executors).
//! The adapter inherits that trade-off rather than widening it;
//! when rules migrate to consume the substrate, the matcher set can
//! be extended (e.g. an `MethodCallAnyReceiver { method: "query" }`
//! gated by a mysql2-import propagation pass) or the rule can fall
//! back to inline heuristics for the unconventional-receiver gap.
//!
//! ## Sources, sanitisers, guards
//!
//! None. mysql2 is a sink-only surface — it doesn't introduce taint
//! and has no built-in sanitisation. Parameterised queries are
//! recognised by the downstream rule based on the second-argument
//! bind array, not by an adapter pattern.
//!
//! ## Activation
//!
//! Default `is_enabled` — active when the project profile contains a
//! [`DataLayerHint::Mysql2`] entry at confidence ≥
//! [`ENABLE_CONFIDENCE_FLOOR`] (`0.60`). The profile crate serialises
//! `Mysql2` as `"mysql2"`, which matches the `mysql2` suffix in this
//! adapter's `data/mysql2` ID.
//!
//! [`DataLayerHint::Mysql2`]: stryx_index::profile::DataLayerHint::Mysql2
//! [`ENABLE_CONFIDENCE_FLOOR`]: crate::adapters::ENABLE_CONFIDENCE_FLOOR

use crate::adapters::{AdapterId, AdapterKind, AstMatcher, SinkKind, SinkPattern, StackAdapter};
use stryx_core::Severity;

pub struct Mysql2Adapter;

static SINKS: &[SinkPattern] = &[
    // ── Raw-SQL: <conn>.query(<sql>, ...) ───────────────────────────
    //
    // Immediate-execution path. The first argument is sent as the
    // literal SQL text; concatenation with user input is the
    // classic injection vector. One pattern per conventional
    // receiver name so each finding carries an attributable ID in
    // reporter output (`data/mysql2/pool-query` etc.).
    SinkPattern {
        id: "data/mysql2/pool-query",
        sink: SinkKind::RawSql,
        matchers: &[AstMatcher::MethodCall {
            receiver: "pool",
            method: "query",
        }],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "data/mysql2/client-query",
        sink: SinkKind::RawSql,
        matchers: &[AstMatcher::MethodCall {
            receiver: "client",
            method: "query",
        }],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "data/mysql2/db-query",
        sink: SinkKind::RawSql,
        matchers: &[AstMatcher::MethodCall {
            receiver: "db",
            method: "query",
        }],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "data/mysql2/connection-query",
        sink: SinkKind::RawSql,
        matchers: &[AstMatcher::MethodCall {
            receiver: "connection",
            method: "query",
        }],
        severity_floor: Severity::Critical,
    },
    // ── Raw-SQL: <conn>.execute(<sql>, ...) ─────────────────────────
    //
    // Prepared-statement path. The driver parameterises the bind
    // array, but the SQL text itself is sent verbatim — so
    // concatenated text in the first argument is still injectable.
    // Same closed-set receiver list as `.query`; the downstream
    // rule decides whether the first argument carries taint.
    SinkPattern {
        id: "data/mysql2/pool-execute",
        sink: SinkKind::RawSql,
        matchers: &[AstMatcher::MethodCall {
            receiver: "pool",
            method: "execute",
        }],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "data/mysql2/client-execute",
        sink: SinkKind::RawSql,
        matchers: &[AstMatcher::MethodCall {
            receiver: "client",
            method: "execute",
        }],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "data/mysql2/db-execute",
        sink: SinkKind::RawSql,
        matchers: &[AstMatcher::MethodCall {
            receiver: "db",
            method: "execute",
        }],
        severity_floor: Severity::Critical,
    },
    SinkPattern {
        id: "data/mysql2/connection-execute",
        sink: SinkKind::RawSql,
        matchers: &[AstMatcher::MethodCall {
            receiver: "connection",
            method: "execute",
        }],
        severity_floor: Severity::Critical,
    },
];

impl StackAdapter for Mysql2Adapter {
    fn id(&self) -> AdapterId {
        AdapterId("data/mysql2")
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
    fn mysql2_adapter_exposes_expected_sink_patterns() {
        // Four conventional receiver names × two methods (`query` and
        // `execute`) = eight sink patterns. The set mirrors the
        // inline `is_sql_sink_call` recogniser's receiver list in
        // `crate::steps::sinks::sql`, extended with the prepared-
        // statement (`.execute`) path that's unique to mysql2.
        let sinks = Mysql2Adapter.sinks();
        assert_eq!(sinks.len(), 8);
        let ids: Vec<&str> = sinks.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"data/mysql2/pool-query"));
        assert!(ids.contains(&"data/mysql2/client-query"));
        assert!(ids.contains(&"data/mysql2/db-query"));
        assert!(ids.contains(&"data/mysql2/connection-query"));
        assert!(ids.contains(&"data/mysql2/pool-execute"));
        assert!(ids.contains(&"data/mysql2/client-execute"));
        assert!(ids.contains(&"data/mysql2/db-execute"));
        assert!(ids.contains(&"data/mysql2/connection-execute"));
    }

    #[test]
    fn mysql2_adapter_is_data_layer_kind() {
        assert_eq!(Mysql2Adapter.kind(), AdapterKind::DataLayer);
        assert_eq!(Mysql2Adapter.id(), AdapterId("data/mysql2"));
    }

    #[test]
    fn mysql2_sinks_floor_at_critical() {
        // Every mysql2 sink is a raw-SQL escape hatch — SQL injection
        // here is OWASP A03:2021 / CWE-89, with database compromise
        // and data exfiltration. There are no `DbWrite` sinks on
        // mysql2 (it's a sink-only, ORM-less surface), so the check
        // is uniform across all eight patterns.
        for sink in Mysql2Adapter.sinks() {
            assert!(
                matches!(sink.sink, SinkKind::RawSql),
                "mysql2 sink {} should be RawSql",
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
    fn is_enabled_returns_true_under_mysql2_profile() {
        // High-confidence mysql2 detection in the profile must
        // activate the adapter via the default `is_enabled` path
        // (matches the `data/<name>` adapter ID suffix against the
        // `DataLayerHint::Mysql2` serde spelling `"mysql2"`).
        let profile = ProjectProfile {
            data_layers: vec![Detected {
                id: DataLayerHint::Mysql2,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(Mysql2Adapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_pg_profile() {
        // A pg-only profile must not activate the mysql2 adapter,
        // even at high confidence — adapter activation is per-name,
        // not per-kind. Both `Pg` and `Mysql2` are `DataLayerHint`
        // variants, but only the matching name wires through
        // `is_enabled_default`. The `data/pg` adapter mirrors the
        // same receiver shape under its own ID and is exercised by
        // its own activation tests.
        let profile = ProjectProfile {
            data_layers: vec![Detected {
                id: DataLayerHint::Pg,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!Mysql2Adapter.is_enabled(&profile));
    }
}
