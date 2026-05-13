"""External Tool Integrations — async wrappers for security testing tools.

Supports: Nuclei, sqlmap, ffuf, Dalfox, XSStrike, Burp Suite API, mitmproxy
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from typing import Any, Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)


class ToolResult:
    """Standardized result from any tool."""
    def __init__(self, tool: str, success: bool, findings: list[dict], raw_output: str = ""):
        self.tool = tool
        self.success = success
        self.findings = findings
        self.raw_output = raw_output


async def _run_tool(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    """Execute a CLI tool asynchronously with timeout."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", "Timeout"


# ── Nuclei ──────────────────────────────────────────

class NucleiRunner:
    """Nuclei template-based vulnerability scanner."""

    async def scan(self, target: str, templates: list[str] | None = None,
                   severity: str = "medium,high,critical", rate: int = 100) -> ToolResult:
        cmd = ["nuclei", "-u", target, "-j", "-severity", severity, "-rate-limit", str(rate), "-silent"]
        if templates:
            for t in templates:
                cmd.extend(["-t", t])

        code, stdout, stderr = await _run_tool(cmd, timeout=600)
        findings = []
        for line in stdout.strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    findings.append({
                        "title": data.get("info", {}).get("name", "Unknown"),
                        "severity": data.get("info", {}).get("severity", "info"),
                        "category": data.get("info", {}).get("classification", {}).get("cwe-id", ["misconfiguration"])[0] if data.get("info", {}).get("classification") else "misconfiguration",
                        "affected_url": data.get("matched-at", target),
                        "description": data.get("info", {}).get("description", ""),
                        "confidence": 0.85,
                        "evidence": {"template": data.get("template-id", ""), "matcher": data.get("matcher-name", "")},
                        "source_tool": "nuclei",
                    })
                except json.JSONDecodeError:
                    pass

        logger.info("Nuclei scan complete", target=target, findings=len(findings))
        return ToolResult("nuclei", code == 0, findings, stdout)

    async def generate_template(self, finding: dict) -> str:
        """Auto-generate a Nuclei template for a finding."""
        template = f"""id: reconx-custom-{finding.get('category', 'check')}
info:
  name: "{finding.get('title', 'Custom Check')}"
  severity: {finding.get('severity', 'medium')}
  description: "{finding.get('description', '')[:200]}"
  tags: reconx,custom

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{finding.get('affected_url', '/')}"
    matchers:
      - type: status
        status:
          - 200
"""
        return template


# ── sqlmap ──────────────────────────────────────────

class SqlmapRunner:
    """sqlmap SQL injection testing wrapper."""

    async def scan(self, url: str, param: str | None = None,
                   level: int = 3, risk: int = 2, batch: bool = True) -> ToolResult:
        cmd = ["sqlmap", "-u", url, "--level", str(level), "--risk", str(risk), "--output-dir=/tmp/sqlmap"]
        if param:
            cmd.extend(["-p", param])
        if batch:
            cmd.append("--batch")

        code, stdout, stderr = await _run_tool(cmd, timeout=600)
        findings = []

        if "is vulnerable" in stdout.lower() or "parameter" in stdout.lower() and "injectable" in stdout.lower():
            findings.append({
                "title": f"SQL Injection confirmed by sqlmap",
                "severity": "critical",
                "category": "sqli",
                "affected_url": url,
                "param": param,
                "confidence": 0.95,
                "evidence": {"tool_output": stdout[-500:]},
                "source_tool": "sqlmap",
                "description": f"sqlmap confirmed SQL injection at {url}",
            })

        return ToolResult("sqlmap", code == 0, findings, stdout)


# ── ffuf ────────────────────────────────────────────

class FfufRunner:
    """ffuf web fuzzer wrapper for directory/parameter fuzzing."""

    async def fuzz(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                   method: str = "GET", rate: int = 100) -> ToolResult:
        # URL must contain FUZZ keyword
        if "FUZZ" not in url:
            url = f"{url}/FUZZ"

        cmd = ["ffuf", "-u", url, "-w", wordlist, "-mc", "200,301,302,403",
               "-rate", str(rate), "-json", "-o", "/dev/stdout", "-s"]

        code, stdout, stderr = await _run_tool(cmd, timeout=300)
        findings = []
        try:
            data = json.loads(stdout)
            for result in data.get("results", []):
                findings.append({
                    "title": f"Directory/file found: {result.get('input', {}).get('FUZZ', '')}",
                    "severity": "info",
                    "category": "data_exposure",
                    "affected_url": result.get("url", ""),
                    "confidence": 0.7,
                    "evidence": {"status": result.get("status"), "length": result.get("length"),
                                 "words": result.get("words")},
                    "source_tool": "ffuf",
                    "description": f"Discovered path: {result.get('url', '')}",
                })
        except json.JSONDecodeError:
            pass

        return ToolResult("ffuf", code == 0, findings, stdout)


# ── Dalfox ──────────────────────────────────────────

class DalfoxRunner:
    """Dalfox XSS scanner wrapper."""

    async def scan(self, url: str, param: str | None = None) -> ToolResult:
        cmd = ["dalfox", "url", url, "--silence", "--format", "json"]
        if param:
            cmd.extend(["-p", param])

        code, stdout, stderr = await _run_tool(cmd, timeout=300)
        findings = []
        for line in stdout.strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    findings.append({
                        "title": f"XSS confirmed by Dalfox: {data.get('type', 'reflected')}",
                        "severity": "high",
                        "category": "xss",
                        "affected_url": data.get("data", url),
                        "param": data.get("param", param),
                        "confidence": 0.9,
                        "evidence": {"payload": data.get("payload", ""), "type": data.get("type", "")},
                        "source_tool": "dalfox",
                        "description": f"Dalfox confirmed XSS vulnerability",
                    })
                except json.JSONDecodeError:
                    pass

        return ToolResult("dalfox", code == 0, findings, stdout)


# ── XSStrike ────────────────────────────────────────

class XSStrikeRunner:
    """XSStrike XSS scanner wrapper."""

    async def scan(self, url: str) -> ToolResult:
        cmd = ["python3", "-m", "xsstrike", "-u", url, "--crawl", "--blind"]
        code, stdout, stderr = await _run_tool(cmd, timeout=300)
        findings = []
        if "vulnerable" in stdout.lower() or "reflection" in stdout.lower():
            findings.append({
                "title": "XSS detected by XSStrike",
                "severity": "high", "category": "xss",
                "affected_url": url, "confidence": 0.8,
                "evidence": {"output": stdout[-300:]},
                "source_tool": "xsstrike",
                "description": "XSStrike detected XSS vulnerability",
            })
        return ToolResult("xsstrike", code == 0, findings, stdout)


# ── Burp Suite Enterprise API ───────────────────────

class BurpSuiteClient:
    """Burp Suite Enterprise Edition REST API client."""

    def __init__(self, base_url: str | None = None, api_key: str | None = None):
        self.base_url = base_url or os.getenv("BURP_API_URL", "https://burp.local:8834")
        self.api_key = api_key or os.getenv("BURP_API_KEY", "")
        self.client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {self.api_key}"},
            verify=False, timeout=30.0,
        )

    async def create_scan(self, url: str, config: str = "default") -> dict:
        resp = await self.client.post(f"{self.base_url}/api/scans", json={
            "scan_configurations": [{"name": config, "type": "NamedConfiguration"}],
            "urls": [url],
        })
        resp.raise_for_status()
        return resp.json()

    async def get_scan_status(self, scan_id: str) -> dict:
        resp = await self.client.get(f"{self.base_url}/api/scans/{scan_id}")
        resp.raise_for_status()
        return resp.json()

    async def get_findings(self, scan_id: str) -> list[dict]:
        resp = await self.client.get(f"{self.base_url}/api/scans/{scan_id}/issues")
        resp.raise_for_status()
        issues = resp.json().get("issues", [])
        findings = []
        for issue in issues:
            sev_map = {"high": "high", "medium": "medium", "low": "low", "information": "info"}
            findings.append({
                "title": issue.get("name", "Unknown"),
                "severity": sev_map.get(issue.get("severity", "").lower(), "info"),
                "category": "misconfiguration",
                "affected_url": issue.get("origin", ""),
                "confidence": {"certain": 0.95, "firm": 0.8, "tentative": 0.5}.get(
                    issue.get("confidence", "tentative"), 0.5),
                "evidence": {"path": issue.get("path", "")},
                "source_tool": "burp_suite",
                "description": issue.get("description", ""),
            })
        return findings


# ── mitmproxy Integration ───────────────────────────

class MitmproxyRunner:
    """mitmproxy integration for traffic interception and analysis."""

    async def start_proxy(self, port: int = 8080, script: str | None = None) -> int:
        """Start mitmproxy in background for traffic capture."""
        cmd = ["mitmdump", "-p", str(port), "--set", "flow_detail=0"]
        if script:
            cmd.extend(["-s", script])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.info("mitmproxy started", port=port, pid=proc.pid)
        return proc.pid

    async def analyze_traffic(self, har_file: str) -> list[dict]:
        """Analyze captured HAR traffic for security issues."""
        findings = []
        try:
            with open(har_file) as f:
                data = json.load(f)
            for entry in data.get("log", {}).get("entries", []):
                url = entry.get("request", {}).get("url", "")
                resp_headers = {h["name"].lower(): h["value"]
                                for h in entry.get("response", {}).get("headers", [])}
                # Check for sensitive data in URLs
                if any(kw in url.lower() for kw in ["token=", "password=", "api_key=", "secret="]):
                    findings.append({
                        "title": "Sensitive data in URL",
                        "severity": "high", "category": "data_exposure",
                        "affected_url": url, "confidence": 0.9,
                        "source_tool": "mitmproxy",
                        "description": f"Sensitive data found in URL parameters",
                    })
        except Exception as e:
            logger.error("HAR analysis failed", error=str(e))
        return findings
