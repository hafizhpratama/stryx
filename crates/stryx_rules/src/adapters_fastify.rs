//! `framework/fastify` adapter — Fastify request/reply patterns.
//!
//! Fastify is a Node-first HTTP framework positioned as a faster,
//! schema-first alternative to Express. Its handler signature is
//! `(request, reply) => …`. The naming diverges from Express in two
//! ways that matter to the analyzer:
//!
//! 1. The request binding is conventionally `request`, not `req`. The
//!    full spelling is what Fastify's official docs and TypeScript
//!    types (`FastifyRequest`) recommend; user code that aliases to
//!    `req` is uncommon and falls outside this adapter's recognised
//!    shape. Projects on Express + Fastify simultaneously get both
//!    adapters' source lists via the registry union.
//! 2. The response binding is `reply`, not `res`, and uses `.send(...)`
//!    as the single primary write method (no separate `json`/`end`/
//!    `write` surface like Express). `.redirect(...)` is the dedicated
//!    redirect method.
//!
//! ## Sources
//!
//! Fastify request data is reached through plain member access on the
//! `request` binding — same shape as Express, different receiver name.
//! Each access is a fresh `UserInput`-tainted value in the handler:
//!
//! - `request.body`     — parsed body (Fastify parses JSON, form,
//!   etc. via its content-type-parser registry)
//! - `request.query`    — URL querystring (parsed per the configured
//!   `querystringParser`)
//! - `request.params`   — matched route parameters
//! - `request.headers`  — request header map (lower-cased keys)
//! - `request.cookies`  — cookie map populated by `@fastify/cookie`
//!   when registered. Fastify ships cookie support as a first-party
//!   plugin rather than middleware, so `request.cookies` is the
//!   canonical shape under the framework's profile even when the
//!   plugin's presence isn't separately profile-detected.
//!
//! ## Sinks
//!
//! `reply` is Fastify's response object. Two methods are modelled:
//!
//! - `reply.send(body)`     — primary body write
//!   (`SinkKind::Response`)
//! - `reply.redirect(url)`  — 30x redirect; CWE-601 surface when
//!   `url` is user-controlled (`SinkKind::Redirect`)
//!
//! ### Known limitation: chained calls
//!
//! Fastify's fluent API permits `reply.code(200).send(body)` and
//! `reply.header('x-foo', 'bar').send(body)`. The substrate's
//! `MethodCall` matcher recognises a dotted-identifier-chain receiver
//! (`expression_matches_dotted_chain` in [`crate::adapters`]) but not
//! a call-expression receiver, so `reply.code(...).send(...)` does
//! *not* fire this adapter's `reply-send` sink. This is the same
//! limitation the Express adapter has for `res.status(200).json(...)`
//! and the same trade-off — covering chained-call receivers would
//! require a new matcher variant. Deferred until a rule needs it.
//!
//! Severity floor on both sinks is `High`: a tainted-secret body-write
//! or a user-controlled redirect URL are both production-severity
//! issues regardless of which Fastify reply method emitted them.
//! Downstream rules may *raise* but not lower this floor.
//!
//! ## Activation
//!
//! Default `is_enabled` — active when the project profile contains a
//! `FrameworkHint::Fastify` entry at confidence ≥ `0.60`
//! ([`crate::adapters::ENABLE_CONFIDENCE_FLOOR`]). The profile crate
//! serialises `Fastify` as `"fastify"` (kebab-case default), which
//! matches the `fastify` suffix in this adapter's `framework/fastify`
//! ID.

use crate::adapters::{
    AdapterId, AdapterKind, AstMatcher, SinkKind, SinkPattern, SourcePattern, StackAdapter,
};
use stryx_core::Severity;
use stryx_taint::TaintLabel;

pub struct FastifyAdapter;

static SOURCES: &[SourcePattern] = &[
    SourcePattern {
        id: "framework/fastify/body",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MemberOnParam {
            receiver: "request",
            property: "body",
        }],
    },
    SourcePattern {
        id: "framework/fastify/query",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MemberOnParam {
            receiver: "request",
            property: "query",
        }],
    },
    SourcePattern {
        id: "framework/fastify/params",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MemberOnParam {
            receiver: "request",
            property: "params",
        }],
    },
    SourcePattern {
        id: "framework/fastify/headers",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MemberOnParam {
            receiver: "request",
            property: "headers",
        }],
    },
    SourcePattern {
        id: "framework/fastify/cookies",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MemberOnParam {
            receiver: "request",
            property: "cookies",
        }],
    },
];

static SINKS: &[SinkPattern] = &[
    SinkPattern {
        id: "framework/fastify/reply-send",
        sink: SinkKind::Response,
        matchers: &[AstMatcher::MethodCall {
            receiver: "reply",
            method: "send",
        }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "framework/fastify/reply-redirect",
        sink: SinkKind::Redirect,
        matchers: &[AstMatcher::MethodCall {
            receiver: "reply",
            method: "redirect",
        }],
        severity_floor: Severity::High,
    },
];

impl StackAdapter for FastifyAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("framework/fastify")
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
    fn fastify_adapter_exposes_expected_source_patterns() {
        let sources = FastifyAdapter.sources();
        assert_eq!(sources.len(), 5);
        let ids: Vec<&str> = sources.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"framework/fastify/body"));
        assert!(ids.contains(&"framework/fastify/query"));
        assert!(ids.contains(&"framework/fastify/params"));
        assert!(ids.contains(&"framework/fastify/headers"));
        assert!(ids.contains(&"framework/fastify/cookies"));
        for s in sources {
            assert_eq!(s.label, TaintLabel::UserInput);
        }
    }

    #[test]
    fn fastify_adapter_exposes_expected_sink_patterns() {
        let sinks = FastifyAdapter.sinks();
        assert_eq!(sinks.len(), 2);
        let ids: Vec<&str> = sinks.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"framework/fastify/reply-send"));
        assert!(ids.contains(&"framework/fastify/reply-redirect"));

        // `reply-send` is a body-write (`SinkKind::Response`);
        // `reply-redirect` is the redirect surface (`SinkKind::Redirect`).
        // Both sit at `Severity::High` — equal-severity production risks.
        for sink in sinks {
            let expected = if sink.id == "framework/fastify/reply-redirect" {
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
    fn fastify_adapter_is_framework_kind() {
        assert_eq!(FastifyAdapter.kind(), AdapterKind::Framework);
        assert_eq!(FastifyAdapter.id(), AdapterId("framework/fastify"));
    }

    #[test]
    fn is_enabled_returns_true_under_fastify_profile() {
        // High-confidence Fastify detection in the profile must
        // activate the adapter via the default `is_enabled` path
        // (matches `framework/<name>` adapter ID suffix against the
        // `FrameworkHint::Fastify` serde spelling `"fastify"`).
        let profile = ProjectProfile {
            frameworks: vec![Detected {
                id: FrameworkHint::Fastify,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(FastifyAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_unrelated_profile() {
        // An Express-only profile must not activate the Fastify adapter,
        // even at high confidence — adapter activation is per-name,
        // not per-kind. This is the cross-adapter isolation guarantee
        // the registry depends on when both Express and Fastify ship.
        let profile = ProjectProfile {
            frameworks: vec![Detected {
                id: FrameworkHint::Express,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!FastifyAdapter.is_enabled(&profile));
    }
}
