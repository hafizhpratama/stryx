//! `framework/next-backend` adapter — Next.js backend surface patterns.
//!
//! Stryx scope for Next.js is **backend only** — route handlers, Pages
//! Router API routes, server actions, middleware, and the runtime/server
//! boundary. The `-backend` suffix in the adapter id is deliberate: the
//! catalogue in [`docs/stacks/README.md`][catalog] mirrors the product
//! boundary in [AGENTS.md] which excludes Next.js client React.
//!
//! Next.js has the most varied request-input shape of any framework
//! Stryx targets, because the two router models expose request data
//! through completely different APIs:
//!
//! - **App Router** (`app/api/*/route.ts`): handlers receive a
//!   `Request` (Web standard) — body via `await req.json()`,
//!   `req.formData()`, `req.text()`, `req.arrayBuffer()`; URL params via
//!   the `searchParams` page-component prop.
//! - **Pages Router** (`pages/api/*.ts`): handlers receive a
//!   Node-shaped `NextApiRequest` — body via `req.body`, query via
//!   `req.query`, headers via `req.headers`, cookies via `req.cookies`.
//!
//! Response sinks span both as well: App Router favours
//! `NextResponse.json` and `NextResponse.redirect` plus the Web-standard
//! `Response.json` / `Response.redirect`; `next/navigation` exports a
//! bare `redirect` callable used in server actions.
//!
//! These shapes are already recognised inline by
//! [`crate::steps::sources::body`] and [`crate::steps::sinks::redirect`].
//! This adapter restates them via the [ADR 0014] substrate so the
//! next-backend stack contributes through the same registry path as
//! every other framework, and rule migration can route through
//! `EnabledAdapters` without behavioural drift.
//!
//! [catalog]: ../../../docs/stacks/README.md
//! [AGENTS.md]: ../../../AGENTS.md
//! [ADR 0014]: ../../../docs/decisions/0014-adapter-substrate-api.md

use crate::adapters::{
    AdapterId, AdapterKind, AstMatcher, SinkKind, SinkPattern, SourcePattern, StackAdapter,
};
use stryx_core::Severity;
use stryx_taint::TaintLabel;

pub struct NextBackendAdapter;

/// Request-input source patterns covering both router models.
///
/// App Router handlers take a Web `Request`, so body access is the
/// `await req.json()` / `req.formData()` / `req.text()` /
/// `req.arrayBuffer()` family. Pages Router handlers take
/// `NextApiRequest`, exposing parsed body/query/headers/cookies as
/// plain member access on the `req` parameter.
///
/// `searchparams` covers the App Router page-component prop. Recognition
/// is bare-name only (`searchParams.X`, not `someObj.searchParams.X`),
/// matching the narrower contract documented on
/// [`crate::steps::sources::body::is_search_params_member`]; the
/// substrate's `MemberOnParam` matcher enforces that same single-ident
/// receiver shape, so the recognised set is byte-identical to the
/// inline recogniser.
static SOURCES: &[SourcePattern] = &[
    // ── App Router (Web Request) ───────────────────────────────────
    SourcePattern {
        id: "framework/next-backend/req-json",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MethodCall {
            receiver: "req",
            method: "json",
        }],
    },
    SourcePattern {
        id: "framework/next-backend/req-formdata",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MethodCall {
            receiver: "req",
            method: "formData",
        }],
    },
    SourcePattern {
        id: "framework/next-backend/req-text",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MethodCall {
            receiver: "req",
            method: "text",
        }],
    },
    SourcePattern {
        id: "framework/next-backend/req-arraybuffer",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MethodCall {
            receiver: "req",
            method: "arrayBuffer",
        }],
    },
    // ── Pages Router (NextApiRequest) ──────────────────────────────
    SourcePattern {
        id: "framework/next-backend/req-body",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MemberOnParam {
            receiver: "req",
            property: "body",
        }],
    },
    SourcePattern {
        id: "framework/next-backend/req-query",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MemberOnParam {
            receiver: "req",
            property: "query",
        }],
    },
    SourcePattern {
        id: "framework/next-backend/req-cookies",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MemberOnParam {
            receiver: "req",
            property: "cookies",
        }],
    },
    SourcePattern {
        id: "framework/next-backend/req-headers",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MemberOnParam {
            receiver: "req",
            property: "headers",
        }],
    },
    // ── App Router page props ──────────────────────────────────────
    SourcePattern {
        id: "framework/next-backend/searchparams",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::MemberOnParam {
            receiver: "searchParams",
            property: "*",
        }],
    },
];

/// Response and redirect sinks for the Next.js backend surface.
///
/// `NextResponse.*` is the App Router framework helper; `Response.*` is
/// the Web platform built-in (returned directly from App Router
/// handlers). Both are recognised via `NamespaceCall` — receiver is a
/// bare identifier in both cases.
///
/// The bare `redirect(...)` form is the `next/navigation` server-action
/// helper. We route this through `ImportedCall` rather than treating
/// every bare `redirect` call as a sink, because in non-Next.js code a
/// `redirect` identifier could be a local function. The matcher
/// consults the per-file import map to confirm the binding came from
/// `next/navigation`. Note that this differs from the inline
/// recogniser in [`crate::steps::sinks::redirect`], which treats any
/// bare `redirect(...)` as a sink — the import-map gate is the safer
/// shape for the substrate path and reduces false positives in non
/// Next.js files that happen to define a local helper named `redirect`.
///
/// All redirect sinks share `Severity::High` (CWE-601) and all response
/// sinks share `Severity::High` (the response-secret rule treats
/// secret-leak flows as high-severity by default).
static SINKS: &[SinkPattern] = &[
    SinkPattern {
        id: "framework/next-backend/nextresponse-json",
        sink: SinkKind::Response,
        matchers: &[AstMatcher::NamespaceCall {
            namespace: "NextResponse",
            member: "json",
        }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "framework/next-backend/nextresponse-redirect",
        sink: SinkKind::Redirect,
        matchers: &[AstMatcher::NamespaceCall {
            namespace: "NextResponse",
            member: "redirect",
        }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "framework/next-backend/response-json",
        sink: SinkKind::Response,
        matchers: &[AstMatcher::NamespaceCall {
            namespace: "Response",
            member: "json",
        }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "framework/next-backend/response-redirect",
        sink: SinkKind::Redirect,
        matchers: &[AstMatcher::NamespaceCall {
            namespace: "Response",
            member: "redirect",
        }],
        severity_floor: Severity::High,
    },
    SinkPattern {
        id: "framework/next-backend/redirect",
        sink: SinkKind::Redirect,
        matchers: &[AstMatcher::ImportedCall {
            module: "next/navigation",
            name: "redirect",
        }],
        severity_floor: Severity::High,
    },
];

impl StackAdapter for NextBackendAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("framework/next-backend")
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
    fn next_backend_adapter_exposes_expected_source_patterns() {
        let sources = NextBackendAdapter.sources();
        assert_eq!(sources.len(), 9);
        let ids: Vec<&str> = sources.iter().map(|s| s.id).collect();
        // App Router (Web Request).
        assert!(ids.contains(&"framework/next-backend/req-json"));
        assert!(ids.contains(&"framework/next-backend/req-formdata"));
        assert!(ids.contains(&"framework/next-backend/req-text"));
        assert!(ids.contains(&"framework/next-backend/req-arraybuffer"));
        // Pages Router (NextApiRequest).
        assert!(ids.contains(&"framework/next-backend/req-body"));
        assert!(ids.contains(&"framework/next-backend/req-query"));
        assert!(ids.contains(&"framework/next-backend/req-cookies"));
        assert!(ids.contains(&"framework/next-backend/req-headers"));
        // App Router page prop.
        assert!(ids.contains(&"framework/next-backend/searchparams"));
        // Every request-input source contributes UserInput taint.
        for s in sources {
            assert_eq!(s.label, TaintLabel::UserInput);
        }
    }

    #[test]
    fn next_backend_adapter_exposes_expected_sink_patterns() {
        let sinks = NextBackendAdapter.sinks();
        assert_eq!(sinks.len(), 5);
        let ids: Vec<&str> = sinks.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"framework/next-backend/nextresponse-json"));
        assert!(ids.contains(&"framework/next-backend/nextresponse-redirect"));
        assert!(ids.contains(&"framework/next-backend/response-json"));
        assert!(ids.contains(&"framework/next-backend/response-redirect"));
        assert!(ids.contains(&"framework/next-backend/redirect"));
        // Every sink ships with a `High` severity floor — rules may
        // raise but not lower this per the substrate contract.
        for s in sinks {
            assert_eq!(s.severity_floor, Severity::High);
        }
        // Sink-kind split: 2 Response, 3 Redirect.
        let response_count = sinks
            .iter()
            .filter(|s| s.sink == SinkKind::Response)
            .count();
        let redirect_count = sinks
            .iter()
            .filter(|s| s.sink == SinkKind::Redirect)
            .count();
        assert_eq!(response_count, 2);
        assert_eq!(redirect_count, 3);
    }

    #[test]
    fn next_backend_adapter_is_framework_kind() {
        assert_eq!(NextBackendAdapter.kind(), AdapterKind::Framework);
        assert_eq!(NextBackendAdapter.id(), AdapterId("framework/next-backend"));
    }

    #[test]
    fn is_enabled_returns_true_under_next_backend_profile() {
        // FrameworkHint::NextBackend serialises as "next-backend" per
        // the kebab-case rename in stryx_index::profile; the substrate
        // default matches the suffix of `framework/next-backend`
        // against that string at confidence >= 0.60.
        let profile = ProjectProfile {
            frameworks: vec![Detected {
                id: FrameworkHint::NextBackend,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(NextBackendAdapter.is_enabled(&profile));
    }

    #[test]
    fn is_enabled_returns_false_under_unrelated_profile() {
        // Express detected at high confidence must not activate the
        // next-backend adapter — adapters are stack-scoped by design.
        let profile = ProjectProfile {
            frameworks: vec![Detected {
                id: FrameworkHint::Express,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        assert!(!NextBackendAdapter.is_enabled(&profile));
    }
}
