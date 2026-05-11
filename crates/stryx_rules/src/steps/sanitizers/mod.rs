//! Sanitiser-step variants (ADR 0008).
//!
//! Slice 8.3a lands [`ParserSanitizer`] — zod/valibot/yup/arktype
//! `<schema>.parse(input)` plus the @conform-to free-function
//! `parse(input, { schema })` shape plus Stripe's
//! `stripe.webhooks.constructEvent(...)`. Subsequent slices add
//! `AuthCheckSanitizer` (8.3b) and `RedactorSanitizer` (8.3c).
//! ADR 0009's `GuardKind` variants slot in here too: a guard is
//! a sanitiser whose effect is branch-scoped.

pub mod parser;

pub use parser::{ParserSanitizer, is_sanitizer_call, second_arg_has_schema_key};
