//! `framework/express` adapter — Express request/response patterns.
//!
//! Express is the longest-lived Node.js HTTP framework and the de-facto
//! shape that many adjacent stacks (Connect, Pages-Router API routes,
//! `express`-compatible middleware on Fastify/Hono interop) imitate.
//! Its handler signature is `(req, res, next) => …`, where `req`
//! exposes user-controlled input through bare member access and `res`
//! is the response surface.
//!
//! ## Sources
//!
//! Express request data is reached through plain member access on the
//! `req` binding — no decorators, no parsing call required. Each member
//! is a fresh `UserInput`-tainted value in the handler's scope:
//!
//! - `req.body`     — parsed JSON / form body (when `body-parser` /
//!   `express.json()` is enabled)
//! - `req.query`    — URL querystring map
//! - `req.params`   — matched route parameters
//! - `req.headers`  — request header map (case-insensitive keys)
//!
//! These four are byte-equivalent to what the inline recognisers in
//! [`crate::steps::sources::body`] already accept for the `body` shape;
//! `query`, `params`, and `headers` were not previously named-property
//! sources, so this adapter widens recognition under the
//! `framework/express` profile only — it does not affect projects on
//! Hono, NestJS, or plain Next.js. Cookie support (`req.cookies`,
//! populated by the `cookie-parser` middleware) is intentionally
//! deferred until inline recognisers learn the shape; adding it here
//! would diverge adapter output from rule output on the same project.
//!
//! `req.json()` — the Web-Fetch-style async body parser — is *not*
//! listed: that call shape is already recognised generically by
//! [`crate::steps::sources::body::is_body_source_call`] across `req`,
//! `request`, `c`, and `ctx` receivers, which spans Hono, Next.js, and
//! Express. Attributing it to the Express adapter would double-count
//! when both adapters are active and would mis-attribute on a Hono
//! project. The generic recogniser stays the source of truth for that
//! shape.
//!
//! ## Sinks
//!
//! `res` is Express's response object. Five methods write to it:
//!
//! - `res.json(body)`     — serialises `body` as JSON
//! - `res.send(body)`     — sends a string / buffer / object body
//! - `res.end(body?)`     — terminates the response, optional final chunk
//! - `res.write(chunk)`   — streams a chunk to the response
//! - `res.redirect(url)`  — 30x redirect; CWE-601 surface when `url`
//!   is user-controlled
//!
//! `json`/`send`/`end`/`write` reach the same downstream behaviour
//! (`SinkKind::Response`) — they're all "secret reached the wire"
//! signals for `flow/secret-to-response`. `redirect` is split out as
//! `SinkKind::Redirect` so `flow/redirect-open` can target it
//! specifically.
//!
//! Severity floor on every response sink is `High`: a body-write of
//! tainted secret material is the same severity regardless of which
//! Express method emitted it; downstream rules may *raise* but not
//! lower this floor.
//!
//! ## Activation
//!
//! Default `is_enabled` — active when the project profile contains a
//! `FrameworkHint::Express` entry at confidence ≥ `0.60`
//! ([`crate::adapters::ENABLE_CONFIDENCE_FLOOR`]). The profile crate
//! serialises `Express` as `"express"`, which matches the `express`
//! suffix in this adapter's `framework/express` ID.

use crate::adapters::{
    AdapterId, AdapterKind, AstMatcher, SinkKind, SinkPattern, SourcePattern, StackAdapter,
};
use stryx_core::Severity;
use stryx_taint::TaintLabel;

pub struct ExpressAdapter;

static SOURCES: &[SourcePattern] = &[
    SourcePattern {
        id: "framework/express/body",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MemberOnParam {
            receiver: "req",
            property: "body",
        }],
    },
    SourcePattern {
        id: "framework/express/query",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MemberOnParam {
            receiver: "req",
            property: "query",
        }],
    },
    SourcePattern {
        id: "framework/express/params",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MemberOnParam {
            receiver: "req",
            property: "params",
        }],
    },
    SourcePattern {
        id: "framework/express/headers",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MemberOnParam {
            receiver: "req",
            property: "headers",
        }],
    },
];

static SINKS: &[SinkPattern] = &[
    SinkPattern {
        id: "framework/express/res-json",
        sink: SinkKind::Response,
        matchers: &[AstMatcher::MethodCall {
            receiver: "res",
            method: "json",
        }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "framework/express/res-send",
        sink: SinkKind::Response,
        matchers: &[AstMatcher::MethodCall {
            receiver: "res",
            method: "send",
        }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "framework/express/res-end",
        sink: SinkKind::Response,
        matchers: &[AstMatcher::MethodCall {
            receiver: "res",
            method: "end",
        }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "framework/express/res-write",
        sink: SinkKind::Response,
        matchers: &[AstMatcher::MethodCall {
            receiver: "res",
            method: "write",
        }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "framework/express/res-redirect",
        sink: SinkKind::Redirect,
        matchers: &[AstMatcher::MethodCall {
            receiver: "res",
            method: "redirect",
        }],
        severity_floor: Severity::High,
    },
];

impl StackAdapter for ExpressAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("framework/express")
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
    fn express_adapter_exposes_expected_source_patterns() {
        let sources = ExpressAdapter.sources();
        assert_eq!(sources.len(), 4);
        let ids: Vec<&str> = sources.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"framework/express/body"));
        assert!(ids.contains(&"framework/express/query"));
        assert!(ids.contains(&"framework/express/params"));
        assert!(ids.contains(&"framework/express/headers"));
        for s in sources {
            assert_eq!(s.label, TaintLabel::UserInput);
        }
    }

    #[test]
    fn express_adapter_exposes_expected_sink_patterns() {
        let sinks = ExpressAdapter.sinks();
        assert_eq!(sinks.len(), 5);
        let ids: Vec<&str> = sinks.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"framework/express/res-json"));
        assert!(ids.contains(&"framework/express/res-send"));
        assert!(ids.contains(&"framework/express/res-end"));
        assert!(ids.contains(&"framework/express/res-write"));
        assert!(ids.contains(&"framework/express/res-redirect"));

        // Response-body sinks all carry `SinkKind::Response`; only
        // `res-redirect` diverges with `SinkKind::Redirect`.
        for sink in sinks {
            let expected = if sink.id == "framework/express/res-redirect" {
                SinkKind::Redirect
            } else {
                SinkKind::Response
            };
            assert_eq!(sink.sink, expected, "sink kind mismatch on {}", sink.id);
            assert_eq!(
                sink.severity_floor,
                Severity::High,
                "severity floor mismatch on {}",
                sink.id
            );
        }
    }

    #[test]
    fn express_adapter_is_framework_kind() {
        assert_eq!(ExpressAdapter.kind(), AdapterKind::Framework);
        assert_eq!(ExpressAdapter.id(), AdapterId("framework/express"));
    }

    #[test]
    fn is_enabled_returns_true_under_express_profile() {
        // High-confidence Express detection in the profile must
        // activate the adapter via the default `is_enabled` path
        // (matches `framework/<name>` adapter ID suffix against the
        // `FrameworkHint::Express` serde spelling `"express"`).
        let profile = ProjectProfile {
            frameworks: vec![Detected {
                id: FrameworkHint::Express,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(ExpressAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_unrelated_profile() {
        // A Hono-only profile must not activate the Express adapter,
        // even at high confidence — adapter activation is per-name,
        // not per-kind.
        let profile = ProjectProfile {
            frameworks: vec![Detected {
                id: FrameworkHint::Hono,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!ExpressAdapter.is_enabled(&profile));
    }
}
