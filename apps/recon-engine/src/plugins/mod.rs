//! Plugin trait system for extensible recon tools.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

/// Trait that all recon tool plugins must implement.
#[async_trait]
pub trait ReconPlugin: Send + Sync {
    /// Unique name of this plugin.
    fn name(&self) -> &str;

    /// Description of what this plugin does.
    fn description(&self) -> &str;

    /// The recon phase this plugin belongs to.
    fn phase(&self) -> &str;

    /// Version of the plugin.
    fn version(&self) -> &str {
        "0.1.0"
    }

    /// Check if the external tool is available/installed.
    async fn is_available(&self) -> bool;

    /// Execute the plugin against a list of targets.
    /// Returns structured JSON results.
    async fn execute(&self, targets: &[String]) -> Result<Vec<Value>>;

    /// Validate plugin-specific configuration.
    fn validate_config(&self, _config: &Value) -> Result<()> {
        Ok(())
    }
}

/// Plugin manifest for registration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub phase: String,
    pub author: String,
    pub requires: Vec<String>,       // External tool dependencies
    pub supported_os: Vec<String>,   // linux, darwin, windows
}
