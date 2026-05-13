# ReconX Plugin Development Guide

## Plugin Architecture

ReconX uses a modular plugin system. Every recon tool, platform integration,
and AI capability is a plugin that conforms to a standard interface.

## Plugin Types

### 1. Recon Tool Plugins
Wrap external recon tools (subfinder, httpx, naabu, etc.)

### 2. Platform Integration Plugins
Connect to bug bounty platforms (HackerOne, Bugcrowd, etc.)

### 3. AI Plugins
Custom AI analysis and scoring modules

---

## Creating a Recon Tool Plugin

### Directory Structure

```
plugins/recon-tools/my-tool/
├── manifest.json
├── plugin.py           # Python wrapper
├── plugin.rs           # Optional Rust wrapper
├── README.md
└── tests/
    └── test_plugin.py
```

### manifest.json

```json
{
    "name": "my-tool",
    "version": "1.0.0",
    "description": "Description of what this tool does",
    "phase": "subdomain_enumeration",
    "author": "Your Name",
    "requires": ["my-tool-binary"],
    "supported_os": ["linux", "darwin"],
    "config_schema": {
        "timeout": {"type": "integer", "default": 300},
        "threads": {"type": "integer", "default": 10}
    }
}
```

### Python Plugin Template

```python
from reconx_shared.plugins import BasePlugin, PluginResult

class MyToolPlugin(BasePlugin):
    name = "my-tool"
    phase = "subdomain_enumeration"

    async def is_available(self) -> bool:
        return await self.check_binary("my-tool")

    async def execute(self, targets: list[str], config: dict) -> list[PluginResult]:
        results = []
        for target in targets:
            output = await self.run_command(
                ["my-tool", "-d", target, "-silent"],
                timeout=config.get("timeout", 300)
            )
            for line in output.splitlines():
                results.append(PluginResult(
                    type="subdomain",
                    value=line.strip(),
                    source=self.name,
                    target=target,
                ))
        return results
```

### Rust Plugin Template

Implement the `ReconPlugin` trait in `apps/recon-engine/src/plugins/mod.rs`:

```rust
use async_trait::async_trait;
use crate::plugins::ReconPlugin;

pub struct MyToolPlugin;

#[async_trait]
impl ReconPlugin for MyToolPlugin {
    fn name(&self) -> &str { "my-tool" }
    fn description(&self) -> &str { "My custom tool" }
    fn phase(&self) -> &str { "subdomain_enumeration" }

    async fn is_available(&self) -> bool {
        tokio::process::Command::new("my-tool")
            .arg("--version")
            .output().await.is_ok()
    }

    async fn execute(&self, targets: &[String]) -> anyhow::Result<Vec<serde_json::Value>> {
        // Implementation here
        Ok(vec![])
    }
}
```

---

## Creating a Platform Integration Plugin

```
plugins/integrations/my-platform/
├── manifest.json
├── client.py          # API client
├── scope_parser.py    # Scope extraction logic
└── tests/
```

### Example: HackerOne Integration

```python
import httpx

class HackerOneClient:
    BASE_URL = "https://api.hackerone.com/v1"

    def __init__(self, username: str, api_token: str):
        self.client = httpx.AsyncClient(
            auth=(username, api_token),
            headers={"Accept": "application/json"}
        )

    async def get_program_scopes(self, handle: str) -> list[dict]:
        resp = await self.client.get(
            f"{self.BASE_URL}/hackers/programs/{handle}"
        )
        resp.raise_for_status()
        data = resp.json()

        scopes = []
        for attr in data["relationships"]["structured_scopes"]["data"]:
            scope = attr["attributes"]
            scopes.append({
                "value": scope["asset_identifier"],
                "type": scope["asset_type"],
                "eligible_for_bounty": scope["eligible_for_bounty"],
                "eligible_for_submission": scope["eligible_for_submission"],
            })
        return scopes
```

---

## Plugin Registration

Plugins are auto-discovered from the `plugins/` directory. Add your plugin
directory and it will be loaded at startup based on the `manifest.json`.

## Testing

```bash
# Run plugin tests
pytest plugins/recon-tools/my-tool/tests/ -v
```
