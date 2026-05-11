//! Sanitiser-step variants (ADR 0008).
//!
//! Substrate-only at slice 8.1. Variants land at slice 8.3 —
//! `ParserSanitizer` (zod/valibot/yup), `AuthCheckSanitizer`,
//! `RedactorSanitizer`. ADR 0009's `GuardKind` variants slot in
//! here too: a guard is a sanitiser whose effect is branch-scoped.
