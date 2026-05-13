//! Port scanning — wraps naabu, rustscan.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;
use tracing::info;

use crate::plugins::ReconPlugin;

pub struct NaabuPlugin;

#[async_trait]
impl ReconPlugin for NaabuPlugin {
    fn name(&self) -> &str { "naabu" }
    fn description(&self) -> &str { "Fast port scanning using naabu" }
    fn phase(&self) -> &str { "port_scanning" }

    async fn is_available(&self) -> bool {
        Command::new("naabu").arg("-version").output().await.is_ok()
    }

    async fn execute(&self, targets: &[String]) -> Result<Vec<Value>> {
        let input = targets.join("\n");
        let mut child = Command::new("naabu")
            .args(["-silent", "-json", "-top-ports", "1000"])
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

        info!(count = results.len(), "naabu completed");
        Ok(results)
    }
}
