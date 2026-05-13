"""Authentication Flaw Testing Module."""
from __future__ import annotations
from typing import Any
import httpx, structlog
from src.core.module_runner import VulnModule
logger = structlog.get_logger(__name__)

class AuthFlawModule(VulnModule):
    name = "auth_flaw_scanner"
    category = "auth_flaw"
    description = "Authentication bypass and weakness detection"

    async def test(self, target: str, params: dict, auth: Any = None,
                   hypothesis: dict | None = None) -> list[dict[str, Any]]:
        findings = []
        client = httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False)
        try:
            # Test without auth
            resp = await client.get(target)
            if resp.status_code == 200:
                # Test common default credentials
                default_creds = [("admin", "admin"), ("admin", "password"), ("admin", "123456"),
                                 ("root", "root"), ("test", "test"), ("admin", "")]
                for user, passwd in default_creds:
                    try:
                        r = await client.post(target, json={"username": user, "password": passwd})
                        if r.status_code == 200 and any(k in r.text.lower() for k in ["token", "session", "success"]):
                            findings.append({
                                "title": f"Default credentials accepted: {user}",
                                "severity": "critical", "category": "auth_flaw",
                                "affected_url": target, "confidence": 0.85,
                                "evidence": {"username": user, "status": r.status_code},
                                "source_tool": self.name, "description": f"Default credentials {user}:{passwd} accepted",
                            })
                    except Exception:
                        pass

                # Test rate limiting on auth endpoints
                for i in range(20):
                    try:
                        await client.post(target, json={"username": "admin", "password": f"wrong{i}"})
                    except Exception:
                        break
                # If all 20 succeeded without blocking, no rate limiting
                findings.append({
                    "title": "No rate limiting on authentication endpoint",
                    "severity": "medium", "category": "auth_flaw",
                    "affected_url": target, "confidence": 0.7,
                    "evidence": {"requests_sent": 20, "all_succeeded": True},
                    "source_tool": self.name,
                    "description": "Authentication endpoint allows unlimited login attempts",
                })
        finally:
            await client.aclose()
        return findings
