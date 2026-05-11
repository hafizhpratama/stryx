//! Sanitiser-step variants (ADR 0008).
//!
//! Slice 8.3a lands [`ParserSanitizer`] — zod/valibot/yup/arktype
//! `<schema>.parse(input)` plus the @conform-to free-function
//! `parse(input, { schema })` shape plus Stripe's
//! `stripe.webhooks.constructEvent(...)`. Subsequent slices add
//! `AuthCheckSanitizer` (8.3b) and `RedactorSanitizer` (8.3c).
//! ADR 0009's `GuardKind` variants slot in here too: a guard is
//! a sanitiser whose effect is branch-scoped.

pub mod auth;
pub mod parser;
pub mod redactor;
pub mod url_allowlist;

pub use auth::{AUTH_HELPER_NAMES, AuthCheckSanitizer, call_invokes_auth_helper};
pub use parser::{ParserSanitizer, is_sanitizer_call, second_arg_has_schema_key};
pub use redactor::{REDACT_FN_NAMES, RedactorSanitizer, is_boolean_coercion, is_redactor_call};
pub use url_allowlist::{branch_returns, extract_url_constructor_input, match_url_allow_list_guard};
