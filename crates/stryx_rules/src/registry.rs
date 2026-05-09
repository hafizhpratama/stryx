use crate::{flows, generic, Rule};
use std::sync::Arc;

/// Registry of all enabled rules for a scan. Rules are stored as `Arc<dyn Rule>`
/// so the registry can be cheaply shared across rayon workers.
#[derive(Clone, Default)]
pub struct RuleRegistry {
    rules: Vec<Arc<dyn Rule>>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, rule: Arc<dyn Rule>) -> &mut Self {
        self.rules.push(rule);
        self
    }

    pub fn rules(&self) -> &[Arc<dyn Rule>] {
        &self.rules
    }
}

/// All rules shipped with v0.0.1.
pub fn builtin_rules() -> RuleRegistry {
    let mut reg = RuleRegistry::new();
    reg.register(Arc::new(generic::HardcodedSecret::new()));
    reg.register(Arc::new(flows::UnvalidatedBodyToDb::new()));
    reg
}
