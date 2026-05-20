//! `framework/nestjs` adapter — NestJS source patterns.
//!
//! NestJS uses decorator-based parameter binding to inject request
//! data into controller methods. Each decorator introduces a fresh
//! UserInput-tainted value into the handler's scope:
//!
//! - `@Body() dto`      — request body, validated/transformed via DTO class
//! - `@Query() q`       — URL query parameters
//! - `@Param('id') id`  — route path parameters
//! - `@Headers() h`     — request headers
//! - `@Req() req`       — full Express/Fastify request object (escape hatch)
//!
//! Rules consume these via the AstMatcher::DecoratedParam matcher from
//! the substrate (ADR 0014). The matcher itself recognises the
//! decorator at parameter-declaration sites — that wiring lands in a
//! separate slice (rule migration). At ship time, this adapter is
//! "registered but inactive" until rules begin consuming
//! `ctx.match_source` on decorated parameters.

use crate::adapters::{AdapterId, AdapterKind, AstMatcher, SourcePattern, StackAdapter};
use stryx_taint::TaintLabel;

pub struct NestJsAdapter;

static SOURCES: &[SourcePattern] = &[
    SourcePattern {
        id: "framework/nestjs/body",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::DecoratedParam { decorator: "Body" }],
    },
    SourcePattern {
        id: "framework/nestjs/query",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::DecoratedParam { decorator: "Query" }],
    },
    SourcePattern {
        id: "framework/nestjs/param",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::DecoratedParam { decorator: "Param" }],
    },
    SourcePattern {
        id: "framework/nestjs/headers",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::DecoratedParam {
            decorator: "Headers",
        }],
    },
    SourcePattern {
        id: "framework/nestjs/req",
        label: TaintLabel::UserInput,
        matchers: &[AstMatcher::DecoratedParam { decorator: "Req" }],
    },
];

impl StackAdapter for NestJsAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("framework/nestjs")
    }
    fn kind(&self) -> AdapterKind {
        AdapterKind::Framework
    }
    fn sources(&self) -> &'static [SourcePattern] {
        SOURCES
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::AdapterRegistry;
    use stryx_index::profile::{Detected, FrameworkHint, ProjectProfile};

    #[test]
    fn nestjs_adapter_exposes_five_source_patterns() {
        let sources = NestJsAdapter.sources();
        assert_eq!(sources.len(), 5);
        let ids: Vec<&str> = sources.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"framework/nestjs/body"));
        assert!(ids.contains(&"framework/nestjs/query"));
        assert!(ids.contains(&"framework/nestjs/param"));
        assert!(ids.contains(&"framework/nestjs/headers"));
        assert!(ids.contains(&"framework/nestjs/req"));
        for s in sources {
            assert_eq!(s.label, TaintLabel::UserInput);
        }
    }

    #[test]
    fn enabled_for_nestjs_profile_activates_nestjs_adapter() {
        let profile = ProjectProfile {
            frameworks: vec![Detected {
                id: FrameworkHint::NestJs,
                confidence: 0.90,
                evidence: vec![],
            }],
            ..Default::default()
        };
        let reg = AdapterRegistry::builtin();
        let enabled = reg.enabled_for(&profile);
        assert!(!enabled.is_empty());
        assert_eq!(enabled.sources.len(), 5);
        assert!(
            enabled
                .active
                .iter()
                .any(|a| a.id() == AdapterId("framework/nestjs"))
        );
    }

    #[test]
    fn enabled_for_non_nestjs_profile_does_not_activate_nestjs() {
        let profile = ProjectProfile::default();
        let reg = AdapterRegistry::builtin();
        let enabled = reg.enabled_for(&profile);
        assert!(
            !enabled
                .active
                .iter()
                .any(|a| a.id() == AdapterId("framework/nestjs"))
        );
    }
}
