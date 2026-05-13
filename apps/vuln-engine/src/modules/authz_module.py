"""Authorization Bypass Testing Module."""
from __future__ import annotations
from typing import Any
import httpx, structlog
from src.core.module_runner import VulnModule
logger = structlog.get_logger(__name__)

class AuthzBypassModule(VulnModule):
    name = "authz_bypass_scanner"
    category = "authz_bypass"
    description = "Authorization bypass and privilege escalation detection"

    BYPASS_HEADERS = [
        {"X-Original-URL": "/admin"}, {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-For": "127.0.0.1"}, {"X-Real-IP": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
    ]

    METHOD_OVERRIDES = ["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"]

    async def test(self, target: str, params: dict, auth: Any = None,
                   hypothesis: dict | None = None) -> list[dict[str, Any]]:
        findings = []
        client = httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False)
        try:
            base = await client.get(target)
            # Header-based bypass
            for bypass_header in self.BYPASS_HEADERS:
                try:
                    resp = await client.get(target, headers=bypass_header)
                    if resp.status_code == 200 and base.status_code in (401, 403, 302):
                        findings.append({
                            "title": f"Authorization bypass via {list(bypass_header.keys())[0]}",
                            "severity": "critical", "category": "authz_bypass",
                            "affected_url": target, "confidence": 0.8,
                            "evidence": {"header": bypass_header, "status": resp.status_code},
                            "source_tool": self.name,
                            "description": f"Access control bypassed using header manipulation",
                        })
                except Exception:
                    pass

            # HTTP method override
            for method_header in self.METHOD_OVERRIDES:
                try:
                    resp = await client.post(target, headers={method_header: "GET"})
                    if resp.status_code == 200 and base.status_code in (401, 403, 405):
                        findings.append({
                            "title": f"Method override bypass via {method_header}",
                            "severity": "high", "category": "authz_bypass",
                            "affected_url": target, "confidence": 0.75,
                            "evidence": {"header": method_header, "status": resp.status_code},
                            "source_tool": self.name,
                            "description": f"HTTP method override allows access bypass",
                        })
                except Exception:
                    pass
        finally:
            await client.aclose()
        return findings
