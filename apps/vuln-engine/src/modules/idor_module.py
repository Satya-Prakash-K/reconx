"""IDOR Testing Module — Insecure Direct Object Reference detection."""

from __future__ import annotations
from typing import Any
import httpx, structlog
from src.core.module_runner import VulnModule

logger = structlog.get_logger(__name__)

class IDORModule(VulnModule):
    name = "idor_scanner"
    category = "idor"
    description = "Insecure Direct Object Reference detection"

    async def test(self, target: str, params: dict, auth: Any = None,
                   hypothesis: dict | None = None) -> list[dict[str, Any]]:
        findings = []
        client = httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True)
        try:
            id_params = [p for p in (params or {}) if any(
                kw in p.lower() for kw in ["id", "uid", "user_id", "account", "order", "doc"]
            )]
            for param in id_params:
                original = params.get(param, "1")
                test_values = ["0", "1", "2", "99999", str(int(original) + 1) if original.isdigit() else "2"]
                base_resp = await client.get(target, params=params)
                for val in test_values:
                    p = dict(params)
                    p[param] = val
                    try:
                        resp = await client.get(target, params=p)
                        if resp.status_code == 200 and val != original and len(resp.text) > 100:
                            if resp.text != base_resp.text:
                                findings.append({
                                    "title": f"Potential IDOR via '{param}' parameter",
                                    "description": f"Accessing {target} with {param}={val} returns different data",
                                    "severity": "high", "category": "idor",
                                    "affected_url": target, "param": param,
                                    "confidence": 0.6,
                                    "evidence": {"original_id": original, "test_id": val,
                                                 "status": resp.status_code},
                                    "source_tool": self.name,
                                })
                    except Exception:
                        pass
        finally:
            await client.aclose()
        return findings
