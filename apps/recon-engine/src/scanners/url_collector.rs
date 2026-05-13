//! URL collection — wraps gau, waybackurls, katana.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;
use tracing::info;

use crate::plugins::ReconPlugin;

pub struct KatanaPlugin;

#[async_trait]
impl ReconPlugin for KatanaPlugin {
    fn name(&self) -> &str { "katana" }
    fn description(&self) -> &str { "Web crawling and URL collection using katana" }
    fn phase(&self) -> &str { "url_collection" }

    async fn is_available(&self) -> bool {
        Command::new("katana").arg("-version").output().await.is_ok()
    }

    async fn execute(&self, targets: &[String]) -> Result<Vec<Value>> {
        let mut results = Vec::new();
        for target in targets {
            let output = Command::new("katana")
                .args(["-u", target, "-silent", "-json", "-depth", "3",
                       "-js-crawl", "-known-files", "all"])
                .output().await?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Ok(parsed) = serde_json::from_str::<Value>(line) {
                    results.push(parsed);
                }
            }
        }
        info!(count = results.len(), "katana completed");
        Ok(results)
    }
}

pub struct GauPlugin;

#[async_trait]
impl ReconPlugin for GauPlugin {
    fn name(&self) -> &str { "gau" }
    fn description(&self) -> &str { "Fetch known URLs from AlienVault, Wayback, Common Crawl" }
    fn phase(&self) -> &str { "url_collection" }

    async fn is_available(&self) -> bool {
        Command::new("gau").arg("--version").output().await.is_ok()
    }

    async fn execute(&self, targets: &[String]) -> Result<Vec<Value>> {
        let mut results = Vec::new();
        for target in targets {
            let output = Command::new("gau")
                .args(["--subs", target])
                .output().await?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let url = line.trim();
                if !url.is_empty() {
                    results.push(json!({"url": url, "source": "gau", "domain": target}));
                }
            }
        }
        info!(count = results.len(), "gau completed");
        Ok(results)
    }
}
