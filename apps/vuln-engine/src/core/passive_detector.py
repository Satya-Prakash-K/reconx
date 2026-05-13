"""Passive Vulnerability Detector — checks without sending attack payloads."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)


class PassiveDetector:
    """Detects vulnerabilities through passive analysis of responses."""

    SECURITY_HEADERS = {
        "strict-transport-security": ("HSTS missing", "medium"),
        "content-security-policy": ("CSP missing", "medium"),
        "x-content-type-options": ("X-Content-Type-Options missing", "low"),
        "x-frame-options": ("X-Frame-Options missing", "low"),
        "x-xss-protection": ("X-XSS-Protection missing", "info"),
        "referrer-policy": ("Referrer-Policy missing", "info"),
        "permissions-policy": ("Permissions-Policy missing", "info"),
    }

    CORS_MISCONFIG_ORIGINS = [
        "https://evil.com",
        "null",
        "https://attacker.example.com",
    ]

    async def detect(self, urls: list[str], categories: list) -> list[dict[str, Any]]:
        """Run passive detection across all URLs."""
        findings: list[dict[str, Any]] = []
        client = httpx.AsyncClient(timeout=15.0, follow_redirects=True, verify=False)

        try:
            for url in urls[:200]:  # Limit for safety
                try:
                    resp = await client.get(url)
                    findings.extend(self._check_security_headers(url, resp))
                    findings.extend(self._check_cors(url, resp))
                    findings.extend(self._check_cookies(url, resp))
                    findings.extend(self._check_info_disclosure(url, resp))
                    findings.extend(await self._check_cors_misconfiguration(url, client))
                except Exception as e:
                    logger.debug("Passive check failed", url=url, error=str(e))
        finally:
            await client.aclose()

        logger.info("Passive detection complete", urls=len(urls), findings=len(findings))
        return findings

    def _check_security_headers(self, url: str, resp: httpx.Response) -> list[dict]:
        findings = []
        for header, (title, severity) in self.SECURITY_HEADERS.items():
            if header not in (h.lower() for h in resp.headers):
                findings.append({
                    "title": title,
                    "description": f"The response from {url} is missing the {header} security header.",
                    "severity": severity,
                    "category": "misconfiguration",
                    "affected_url": url,
                    "evidence": {"missing_header": header, "status_code": resp.status_code},
                    "confidence": 0.95,
                    "source_tool": "passive_detector",
                })
        return findings

    def _check_cookies(self, url: str, resp: httpx.Response) -> list[dict]:
        findings = []
        for cookie_header in resp.headers.get_list("set-cookie"):
            cookie_lower = cookie_header.lower()
            if "secure" not in cookie_lower and url.startswith("https"):
                findings.append({
                    "title": "Cookie without Secure flag",
                    "description": f"Cookie set without Secure flag on HTTPS endpoint: {url}",
                    "severity": "medium",
                    "category": "misconfiguration",
                    "affected_url": url,
                    "evidence": {"cookie_header": cookie_header[:200]},
                    "confidence": 0.9,
                    "source_tool": "passive_detector",
                })
            if "httponly" not in cookie_lower:
                findings.append({
                    "title": "Cookie without HttpOnly flag",
                    "description": f"Cookie accessible via JavaScript (no HttpOnly): {url}",
                    "severity": "low",
                    "category": "misconfiguration",
                    "affected_url": url,
                    "evidence": {"cookie_header": cookie_header[:200]},
                    "confidence": 0.9,
                    "source_tool": "passive_detector",
                })
        return findings

    def _check_cors(self, url: str, resp: httpx.Response) -> list[dict]:
        findings = []
        acao = resp.headers.get("access-control-allow-origin", "")
        if acao == "*":
            acac = resp.headers.get("access-control-allow-credentials", "")
            if acac.lower() == "true":
                findings.append({
                    "title": "CORS misconfiguration: wildcard with credentials",
                    "description": f"Dangerous CORS config at {url}: Allow-Origin=* with credentials",
                    "severity": "high",
                    "category": "cors_misconfig",
                    "affected_url": url,
                    "evidence": {"acao": acao, "acac": acac},
                    "confidence": 0.95,
                    "source_tool": "passive_detector",
                })
        return findings

    def _check_info_disclosure(self, url: str, resp: httpx.Response) -> list[dict]:
        findings = []
        # Server header disclosure
        server = resp.headers.get("server", "")
        if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/", "php/"]):
            findings.append({
                "title": "Server version disclosure",
                "description": f"Server header reveals version: {server}",
                "severity": "info",
                "category": "data_exposure",
                "affected_url": url,
                "evidence": {"server_header": server},
                "confidence": 1.0,
                "source_tool": "passive_detector",
            })

        # X-Powered-By
        powered = resp.headers.get("x-powered-by", "")
        if powered:
            findings.append({
                "title": "Technology disclosure via X-Powered-By",
                "description": f"X-Powered-By header reveals: {powered}",
                "severity": "info",
                "category": "data_exposure",
                "affected_url": url,
                "evidence": {"x_powered_by": powered},
                "confidence": 1.0,
                "source_tool": "passive_detector",
            })
        return findings

    async def _check_cors_misconfiguration(self, url: str, client: httpx.AsyncClient) -> list[dict]:
        findings = []
        for origin in self.CORS_MISCONFIG_ORIGINS:
            try:
                resp = await client.get(url, headers={"Origin": origin})
                acao = resp.headers.get("access-control-allow-origin", "")
                if acao == origin:
                    findings.append({
                        "title": f"CORS reflects arbitrary origin: {origin}",
                        "description": f"The server at {url} reflects the Origin header {origin} in ACAO",
                        "severity": "high",
                        "category": "cors_misconfig",
                        "affected_url": url,
                        "evidence": {"origin_sent": origin, "acao_received": acao},
                        "confidence": 0.9,
                        "source_tool": "passive_detector",
                    })
            except Exception:
                pass
        return findings
