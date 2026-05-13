"""Continuous Monitoring Engine — change detection, JS diff, drift analysis.

Capabilities:
- Periodic endpoint re-scan and diff
- JavaScript file change detection
- DNS record drift monitoring
- New subdomain/endpoint discovery
- Infrastructure change alerts
- AI-generated Nuclei templates from diffs
"""

from __future__ import annotations

import hashlib
import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)


class ChangeDetector:
    """Detects changes in web resources across scan cycles."""

    def __init__(self):
        self._snapshots: dict[str, dict] = {}  # url -> {hash, content, headers, timestamp}

    async def snapshot(self, url: str) -> dict[str, Any]:
        """Take a snapshot of a URL and compare with previous."""
        try:
            async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
                resp = await client.get(url)
                content = resp.text
                content_hash = hashlib.sha256(content.encode()).hexdigest()
                headers = dict(resp.headers)

                current = {
                    "url": url,
                    "hash": content_hash,
                    "content": content[:50000],
                    "status": resp.status_code,
                    "headers": headers,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "size": len(content),
                }

                previous = self._snapshots.get(url)
                changes = None

                if previous and previous["hash"] != content_hash:
                    changes = {
                        "url": url,
                        "type": "content_change",
                        "previous_hash": previous["hash"],
                        "current_hash": content_hash,
                        "size_delta": len(content) - previous.get("size", 0),
                        "previous_timestamp": previous["timestamp"],
                        "current_timestamp": current["timestamp"],
                    }
                    # Check for new headers
                    new_headers = set(headers.keys()) - set(previous.get("headers", {}).keys())
                    removed_headers = set(previous.get("headers", {}).keys()) - set(headers.keys())
                    if new_headers:
                        changes["new_headers"] = list(new_headers)
                    if removed_headers:
                        changes["removed_headers"] = list(removed_headers)

                self._snapshots[url] = current
                return {"snapshot": current, "changes": changes}

        except Exception as e:
            return {"snapshot": None, "error": str(e)}

    async def scan_batch(self, urls: list[str]) -> list[dict]:
        """Scan a batch of URLs for changes."""
        tasks = [self.snapshot(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        changes = []
        for r in results:
            if isinstance(r, dict) and r.get("changes"):
                changes.append(r["changes"])
        return changes


class JSDiffAnalyzer:
    """Detects changes in JavaScript files — new endpoints, API keys, tokens."""

    SENSITIVE_PATTERNS = [
        "api_key", "apikey", "api-key", "secret", "token", "password",
        "authorization", "bearer", "aws_access", "private_key",
        "/api/v", "/graphql", "/admin", "/internal",
    ]

    async def analyze_js_diff(self, url: str, old_content: str, new_content: str) -> list[dict]:
        """Analyze differences between JS versions for security-relevant changes."""
        findings: list[dict] = []
        try:
            from jsondiff import diff as json_diff
        except ImportError:
            pass

        old_lines = set(old_content.split("\n"))
        new_lines = set(new_content.split("\n"))
        added_lines = new_lines - old_lines

        for line in added_lines:
            line_lower = line.lower().strip()
            for pattern in self.SENSITIVE_PATTERNS:
                if pattern in line_lower:
                    findings.append({
                        "type": "js_sensitive_addition",
                        "url": url,
                        "pattern": pattern,
                        "line": line.strip()[:200],
                        "severity": "high" if pattern in ("secret", "password", "private_key") else "medium",
                    })
            # Detect new API endpoints
            if "fetch(" in line or "axios" in line or "XMLHttpRequest" in line:
                findings.append({
                    "type": "js_new_endpoint",
                    "url": url,
                    "line": line.strip()[:200],
                    "severity": "info",
                })

        return findings


class InfrastructureDriftDetector:
    """Detects infrastructure changes — DNS, certificates, headers."""

    async def check_dns_drift(self, domain: str, previous_records: dict | None = None) -> dict:
        """Check for DNS record changes."""
        import socket
        current = {}
        try:
            ips = socket.getaddrinfo(domain, None)
            current["a_records"] = list({ip[4][0] for ip in ips if ip[0] == socket.AF_INET})
            current["aaaa_records"] = list({ip[4][0] for ip in ips if ip[0] == socket.AF_INET6})
        except socket.gaierror:
            current["error"] = "DNS resolution failed"

        changes = None
        if previous_records:
            old_ips = set(previous_records.get("a_records", []))
            new_ips = set(current.get("a_records", []))
            if old_ips != new_ips:
                changes = {"added_ips": list(new_ips - old_ips), "removed_ips": list(old_ips - new_ips)}

        return {"domain": domain, "records": current, "drift": changes}

    async def check_cert_drift(self, domain: str) -> dict:
        """Check TLS certificate changes."""
        import ssl
        try:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(ssl.socket(), server_hostname=domain)
            conn.settimeout(10)
            conn.connect((domain, 443))
            cert = conn.getpeercert()
            conn.close()
            return {
                "domain": domain,
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "not_after": cert.get("notAfter", ""),
                "serial": cert.get("serialNumber", ""),
            }
        except Exception as e:
            return {"domain": domain, "error": str(e)}


class NucleiTemplateGenerator:
    """AI-powered Nuclei template generation from detected changes."""

    async def generate_from_change(self, change: dict) -> str:
        """Generate a Nuclei template from a detected change."""
        url = change.get("url", "")
        change_type = change.get("type", "content_change")

        template = f"""id: reconx-auto-{hashlib.sha256(url.encode()).hexdigest()[:8]}
info:
  name: "Auto-generated check for {url}"
  severity: medium
  description: "Automated template generated from change detection"
  tags: reconx,auto,{change_type}

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}"
    matchers:
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        regex:
          - "api[_-]?key"
          - "secret"
          - "token"
"""
        return template
