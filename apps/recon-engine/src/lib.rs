//! ReconX Recon Engine — Core library with plugin system.

use anyhow::Result;
use dashmap::DashMap;
use std::sync::Arc;
use tracing::info;

use crate::plugins::ReconPlugin;
use crate::scope::ScopeValidator;

/// Core recon engine managing plugins, scope validation, and task execution.
pub struct ReconEngine {
    plugins: Arc<DashMap<String, Box<dyn ReconPlugin>>>,
    scope_validator: Arc<ScopeValidator>,
    redis_url: String,
    kafka_servers: String,
}

impl ReconEngine {
    /// Create a new ReconEngine instance.
    pub async fn new(redis_url: String, kafka_servers: String) -> Result<Self> {
        let plugins: DashMap<String, Box<dyn ReconPlugin>> = DashMap::new();

        // Register built-in scanner plugins
        info!("Registering built-in plugins");

        let engine = Self {
            plugins: Arc::new(plugins),
            scope_validator: Arc::new(ScopeValidator::new()),
            redis_url,
            kafka_servers,
        };

        Ok(engine)
    }

    /// Register a plugin.
    pub fn register_plugin(&self, plugin: Box<dyn ReconPlugin>) {
        let name = plugin.name().to_string();
        info!(plugin = %name, "Registered recon plugin");
        self.plugins.insert(name, plugin);
    }

    /// Get the number of registered plugins.
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    /// Execute a recon phase against validated in-scope targets.
    pub async fn execute_scan(
        &self,
        phase: &str,
        targets: Vec<String>,
    ) -> Result<Vec<serde_json::Value>> {
        // Validate all targets are in scope
        let valid_targets: Vec<String> = targets
            .into_iter()
            .filter(|t| {
                let in_scope = self.scope_validator.is_in_scope(t);
                if !in_scope {
                    tracing::warn!(target = %t, "OUT OF SCOPE — blocked");
                }
                in_scope
            })
            .collect();

        if valid_targets.is_empty() {
            tracing::warn!("No valid in-scope targets");
            return Ok(vec![]);
        }

        let mut results = Vec::new();

        // Execute matching plugins
        for entry in self.plugins.iter() {
            let plugin = entry.value();
            if plugin.phase() == phase {
                info!(plugin = %plugin.name(), targets = valid_targets.len(), "Executing plugin");
                match plugin.execute(&valid_targets).await {
                    Ok(output) => results.extend(output),
                    Err(e) => tracing::error!(plugin = %plugin.name(), error = %e, "Plugin failed"),
                }
            }
        }

        Ok(results)
    }
}
