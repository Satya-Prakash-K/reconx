//! DNS analysis scanner — wraps dnsx, massdns, DNS takeover detection.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;
use tracing::info;

use crate::plugins::ReconPlugin;

pub struct DnsxPlugin;

#[async_trait]
impl ReconPlugin for DnsxPlugin {
    fn name(&self) -> &str { "dnsx" }
    fn description(&self) -> &str { "Fast DNS resolver and record enumeration" }
    fn phase(&self) -> &str { "dns_analysis" }

    async fn is_available(&self) -> bool {
        Command::new("dnsx").arg("-version").output().await.is_ok()
    }

    async fn execute(&self, targets: &[String]) -> Result<Vec<Value>> {
        let input = targets.join("\n");
        let mut child = Command::new("dnsx")
            .args(["-silent", "-json", "-a", "-aaaa", "-cname", "-mx", "-ns", "-resp"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(input.as_bytes()).await?;
        }

        let output = child.wait_with_output().await?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut results = Vec::new();

        for line in stdout.lines() {
            if let Ok(parsed) = serde_json::from_str::<Value>(line) {
                results.push(parsed);
            }
        }

        info!(count = results.len(), "dnsx completed");
        Ok(results)
    }
}
