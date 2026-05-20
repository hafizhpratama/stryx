//! `framework/hono` adapter — Hono request/response patterns.
//!
//! Hono is the dominant Bun- and Edge-runtime web framework. Handlers
//! receive a context object (conventionally bound to `c`) that exposes
//! the request through `c.req.*` and shapes responses through `c.json`,
//! `c.text`, `c.html`, `c.body`, and `c.redirect`. The framework's
//! `c.req` shape differs enough from Express's `req`/`res` split that
//! source/sink recognition must be Hono-specific to stay accurate.
//!
//! Source patterns mirror the inline recognition already in
//! [`crate::steps::sources::body`] for the `c.req.json/text/...`
//! family, so when rules migrate to consume `ctx.match_source` the
//! behaviour stays byte-identical for the existing Hono cases. The
//! adapter additionally contributes patterns the inline path doesn't
//! yet recognise (`c.req.query`, `c.req.param`, `c.req.header`,
//! `c.req.valid`) — these become live the moment rules switch over.
//!
//! Sink patterns cover the Hono response surface:
//!   - `c.json/text/html/body` → `SinkKind::Response`
//!   - `c.redirect`            → `SinkKind::Redirect`
//!
//! ## A note on `c.req.valid('json')`
//!
//! `c.req.valid(...)` returns the value after a middleware-installed
//! validator (e.g. `@hono/zod-validator`) has parsed the request. In
//! a well-configured handler the result is effectively sanitised. We
//! still register it as a source because:
//!
//!   1. A handler that calls `c.req.valid(...)` without the matching
//!      validator middleware reaches the same code path with raw
//!      input — the call site cannot tell which case it's in.
//!   2. Treating it as a source is the safe default; rules can opt
//!      in to "valid-as-sanitiser" via a separate sanitiser pattern
//!      in a later slice without re-flowing the source list.
//!
//! Substrate is per [ADR 0014]; rules begin consuming this adapter in
//! a subsequent slice. At ship time the adapter is "registered but
//! inactive" until rule migration wires `ctx.match_source` /
//! `ctx.match_sink` through to the registry.
//!
//! [ADR 0014]: ../../../docs/decisions/0014-adapter-substrate-api.md

use crate::adapters::{
    AdapterId, AdapterKind, AstMatcher, SinkKind, SinkPattern, SourcePattern, StackAdapter,
};
use stryx_core::Severity;
use stryx_taint::TaintLabel;

pub struct HonoAdapter;

// =============================================================================
// Source patterns — `c.req.*`
// =============================================================================
//
// Receiver is the dotted chain `"c.req"` because `c.req.json()` is a
// method call on `c.req`, not on `c`. The substrate's `MethodCall`
// matcher walks dotted-identifier receivers via
// `expression_matches_dotted_chain`, so `"c.req"` is the literal
// chain string the matcher expects.

static SOURCES: &[SourcePattern] = &[
    // Body parsers — the four shapes the inline recogniser in
    // `steps::sources::body` already handles. Listed individually so
    // the registry view exposes one ID per syntactic shape (useful
    // for reporter grouping and future per-source suppression).
    SourcePattern {
        id: "framework/hono/req-json",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MethodCall {
            receiver: "c.req",
            method: "json",
        }],
    },
    SourcePattern {
        id: "framework/hono/req-text",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MethodCall {
            receiver: "c.req",
            method: "text",
        }],
    },
    SourcePattern {
        id: "framework/hono/req-arraybuffer",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MethodCall {
            receiver: "c.req",
            method: "arrayBuffer",
        }],
    },
    SourcePattern {
        id: "framework/hono/req-formdata",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MethodCall {
            receiver: "c.req",
            method: "formData",
        }],
    },
    // Query helpers. Hono exposes `c.req.query()` (single value /
    // record) and `c.req.queries()` (multi-value array form) — both
    // surface URL-derived input and must be tainted.
    SourcePattern {
        id: "framework/hono/req-query",
        label: TaintLabel::UserInput,
        matchers: &[
            AstMatcher::MethodCall {
                receiver: "c.req",
                method: "query",
            },
            AstMatcher::MethodCall {
                receiver: "c.req",
                method: "queries",
            },
        ],
    },
    // Path parameters — `c.req.param()` returns the route's path
    // params, untrusted URL fragments.
    SourcePattern {
        id: "framework/hono/req-param",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MethodCall {
            receiver: "c.req",
            method: "param",
        }],
    },
    // Request headers — `c.req.header()` returns header values, which
    // are attacker-controlled (e.g. for SSRF or auth-spoofing flows).
    SourcePattern {
        id: "framework/hono/req-header",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MethodCall {
            receiver: "c.req",
            method: "header",
        }],
    },
    // Middleware-validated input. See the module-level note above on
    // why this is registered as a source even though it's usually
    // effectively sanitised at runtime.
    SourcePattern {
        id: "framework/hono/req-valid",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MethodCall {
            receiver: "c.req",
            method: "valid",
        }],
    },
];

// =============================================================================
// Sink patterns — `c.*` response surface
// =============================================================================
//
// Receiver is the single-segment `"c"` — Hono's response helpers
// hang off the context object directly (unlike sources, which hang
// off `c.req`).

static SINKS: &[SinkPattern] = &[
    // JSON response. `severity_floor: High` matches the existing
    // policy for response sinks reached by `Secret` taint
    // (`flow/secret-to-response`).
    SinkPattern {
        id: "framework/hono/c-json",
        sink: SinkKind::Response,
        matchers: &[AstMatcher::MethodCall {
            receiver: "c",
            method: "json",
        }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "framework/hono/c-text",
        sink: SinkKind::Response,
        matchers: &[AstMatcher::MethodCall {
            receiver: "c",
            method: "text",
        }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "framework/hono/c-html",
        sink: SinkKind::Response,
        matchers: &[AstMatcher::MethodCall {
            receiver: "c",
            method: "html",
        }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "framework/hono/c-body",
        sink: SinkKind::Response,
        matchers: &[AstMatcher::MethodCall {
            receiver: "c",
            method: "body",
        }],
        severity_floor: Severity::High,
    },
    // Redirect sink — feeds `flow/redirect-open` when the URL
    // argument carries `UserInput` taint.
    SinkPattern {
        id: "framework/hono/c-redirect",
        sink: SinkKind::Redirect,
        matchers: &[AstMatcher::MethodCall {
            receiver: "c",
            method: "redirect",
        }],
        severity_floor: Severity::High,
    },
];

impl StackAdapter for HonoAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("framework/hono")
    }
    fn kind(&self) -> AdapterKind {
        AdapterKind::Framework
    }
    fn sources(&self) -> &'static [SourcePattern] {
        SOURCES
    }
    fn sinks(&self) -> &'static [SinkPattern] {
        SINKS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stryx_index::profile::{Detected, FrameworkHint, ProjectProfile};

    #[test]
    fn hono_adapter_exposes_expected_source_patterns() {
        let sources = HonoAdapter.sources();
        // One pattern per syntactic shape — see the SOURCES array
        // for the ID-by-ID rationale.
        assert_eq!(sources.len(), 8);
        let ids: Vec<&str> = sources.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"framework/hono/req-json"));
        assert!(ids.contains(&"framework/hono/req-text"));
        assert!(ids.contains(&"framework/hono/req-arraybuffer"));
        assert!(ids.contains(&"framework/hono/req-formdata"));
        assert!(ids.contains(&"framework/hono/req-query"));
        assert!(ids.contains(&"framework/hono/req-param"));
        assert!(ids.contains(&"framework/hono/req-header"));
        assert!(ids.contains(&"framework/hono/req-valid"));
        for s in sources {
            assert_eq!(s.label, TaintLabel::UserInput);
        }
    }

    #[test]
    fn hono_adapter_exposes_expected_sink_patterns() {
        let sinks = HonoAdapter.sinks();
        assert_eq!(sinks.len(), 5);
        let ids: Vec<&str> = sinks.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"framework/hono/c-json"));
        assert!(ids.contains(&"framework/hono/c-text"));
        assert!(ids.contains(&"framework/hono/c-html"));
        assert!(ids.contains(&"framework/hono/c-body"));
        assert!(ids.contains(&"framework/hono/c-redirect"));

        // Response vs Redirect classification — pin the contract so a
        // refactor that flips a sink's kind is caught here.
        for s in sinks {
            let expected = if s.id == "framework/hono/c-redirect" {
                SinkKind::Redirect
            } else {
                SinkKind::Response
            };
            assert_eq!(s.sink, expected, "wrong SinkKind for {}", s.id);
            assert_eq!(
                s.severity_floor,
                Severity::High,
                "wrong severity floor for {}",
                s.id
            );
        }
    }

    #[test]
    fn hono_adapter_is_framework_kind() {
        assert_eq!(HonoAdapter.id(), AdapterId("framework/hono"));
        assert_eq!(HonoAdapter.kind(), AdapterKind::Framework);
    }

    #[test]
    fn is_enabled_returns_true_under_hono_profile() {
        // `FrameworkHint::Hono` at 0.90 is well above the 0.60
        // enable floor — the default `is_enabled` resolution must
        // activate the adapter.
        let profile = ProjectProfile {
            frameworks: vec![Detected {
                id: FrameworkHint::Hono,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(HonoAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_unrelated_profile() {
        // A profile that detected Express but not Hono — the Hono
        // adapter must stay disabled. Guards against the regression
        // where the kind/name split lets a same-kind sibling match.
        let profile = ProjectProfile {
            frameworks: vec![Detected {
                id: FrameworkHint::Express,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!HonoAdapter.is_enabled(&profile));
    }
}
