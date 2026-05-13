//! Subdomain enumeration scanner — wraps subfinder, amass, assetfinder, etc.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;
use tracing::{info, warn};

use crate::plugins::ReconPlugin;

/// Subfinder wrapper plugin.
pub struct SubfinderPlugin;

#[async_trait]
impl ReconPlugin for SubfinderPlugin {
    fn name(&self) -> &str { "subfinder" }
    fn description(&self) -> &str { "Fast passive subdomain enumeration using subfinder" }
    fn phase(&self) -> &str { "subdomain_enumeration" }

    async fn is_available(&self) -> bool {
        Command::new("subfinder").arg("-version")
            .output().await.is_ok()
    }

    async fn execute(&self, targets: &[String]) -> Result<Vec<Value>> {
        let mut results = Vec::new();

        for target in targets {
            info!(target = %target, "Running subfinder");

            let output = Command::new("subfinder")
                .args(["-d", target, "-silent", "-json"])
                .output()
                .await?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Ok(parsed) = serde_json::from_str::<Value>(line) {
                    let host = parsed.get("host")
                        .and_then(|h| h.as_str())
                        .unwrap_or("");
                    if !host.is_empty() {
                        results.push(json!({
                            "subdomain": host,
                            "parent_domain": target,
                            "source": "subfinder",
                        }));
                    }
                }
            }
        }

        info!(count = results.len(), "Subfinder completed");
        Ok(results)
    }
}

/// Amass wrapper plugin.
pub struct AmassPlugin;

#[async_trait]
impl ReconPlugin for AmassPlugin {
    fn name(&self) -> &str { "amass" }
    fn description(&self) -> &str { "In-depth subdomain enumeration using OWASP Amass" }
    fn phase(&self) -> &str { "subdomain_enumeration" }

    async fn is_available(&self) -> bool {
        Command::new("amass").arg("version")
            .output().await.is_ok()
    }

    async fn execute(&self, targets: &[String]) -> Result<Vec<Value>> {
        let mut results = Vec::new();

        for target in targets {
            info!(target = %target, "Running amass enum");
            let output = Command::new("amass")
                .args(["enum", "-passive", "-d", target, "-json", "-"])
                .output()
                .await?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Ok(parsed) = serde_json::from_str::<Value>(line) {
                    let name = parsed.get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("");
                    if !name.is_empty() {
                        results.push(json!({
                            "subdomain": name,
                            "parent_domain": target,
                            "source": "amass",
                        }));
                    }
                }
            }
        }

        Ok(results)
    }
}

/// crt.sh certificate transparency parser.
pub struct CrtShPlugin;

#[async_trait]
impl ReconPlugin for CrtShPlugin {
    fn name(&self) -> &str { "crtsh" }
    fn description(&self) -> &str { "Certificate transparency log enumeration via crt.sh" }
    fn phase(&self) -> &str { "subdomain_enumeration" }

    async fn is_available(&self) -> bool { true } // HTTP-based, always available

    async fn execute(&self, targets: &[String]) -> Result<Vec<Value>> {
        let client = reqwest::Client::new();
        let mut results = Vec::new();

        for target in targets {
            info!(target = %target, "Querying crt.sh");
            let url = format!("https://crt.sh/?q=%.{}&output=json", target);

            match client.get(&url).send().await {
                Ok(resp) => {
                    if let Ok(entries) = resp.json::<Vec<Value>>().await {
                        for entry in entries {
                            if let Some(name) = entry.get("name_value").and_then(|v| v.as_str()) {
                                for subdomain in name.split('\n') {
                                    let sub = subdomain.trim().to_lowercase();
                                    if !sub.is_empty() && !sub.starts_with('*') {
                                        results.push(json!({
                                            "subdomain": sub,
                                            "parent_domain": target,
                                            "source": "crtsh",
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => warn!(error = %e, "crt.sh query failed"),
            }
        }

        Ok(results)
    }
}
