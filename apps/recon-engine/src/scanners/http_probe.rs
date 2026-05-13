//! HTTP probing scanner — wraps httpx.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;
use tracing::info;

use crate::plugins::ReconPlugin;

pub struct HttpxPlugin;

#[async_trait]
impl ReconPlugin for HttpxPlugin {
    fn name(&self) -> &str { "httpx" }
    fn description(&self) -> &str { "HTTP probing with tech detection, WAF detection, TLS info" }
    fn phase(&self) -> &str { "http_probing" }

    async fn is_available(&self) -> bool {
        Command::new("httpx").arg("-version").output().await.is_ok()
    }

    async fn execute(&self, targets: &[String]) -> Result<Vec<Value>> {
        let input = targets.join("\n");
        let mut child = Command::new("httpx")
            .args(["-silent", "-json", "-sc", "-title", "-tech-detect",
                   "-server", "-content-length", "-follow-redirects",
                   "-tls-grab", "-favicon"])
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

        info!(count = results.len(), "httpx completed");
        Ok(results)
    }
}
