//! Simple transport registry / selector.

use crate::config::TransportConfig;
use crate::transport::Transport;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;

/// Factory function type for building boxed transports.
pub type TransportFactory = fn(&TransportConfig) -> Box<dyn Transport>;

/// Registry of named transports.
#[derive(Default)]
pub struct TransportRegistry {
    entries: BTreeMap<&'static str, TransportFactory>,
}

impl TransportRegistry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a transport factory under a name.
    pub fn register(&mut self, name: &'static str, factory: TransportFactory) {
        self.entries.insert(name, factory);
    }

    /// Resolve a transport by name and config.
    pub fn resolve(&self, name: &str, cfg: &TransportConfig) -> Option<Box<dyn Transport>> {
        self.entries.get(name).map(|f| f(cfg))
    }
}
