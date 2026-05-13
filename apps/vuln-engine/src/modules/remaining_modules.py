"""File Upload, Open Redirect, CORS, API Security, Data Exposure, Misconfig, Cloud modules."""
from __future__ import annotations
from typing import Any
import httpx, structlog
from src.core.module_runner import VulnModule
logger = structlog.get_logger(__name__)

class FileUploadModule(VulnModule):
    name = "file_upload_scanner"
    category = "file_upload"
    description = "File upload bypass and dangerous file type testing"
    async def test(self, target: str, params: dict, auth: Any = None, hypothesis: dict | None = None) -> list[dict]:
        findings = []
        client = httpx.AsyncClient(timeout=15.0, verify=False)
        try:
            dangerous_exts = [".php", ".jsp", ".asp", ".aspx", ".py", ".sh", ".svg", ".html"]
            for ext in dangerous_exts:
                files = {"file": (f"test{ext}", b"<?php echo 'test'; ?>", "application/octet-stream")}
                try:
                    resp = await client.post(target, files=files)
                    if resp.status_code in (200, 201):
                        findings.append({"title": f"Dangerous file type accepted: {ext}", "severity": "high",
                            "category": "file_upload", "affected_url": target, "confidence": 0.7,
                            "evidence": {"extension": ext, "status": resp.status_code}, "source_tool": self.name,
                            "description": f"Server accepts {ext} file uploads"})
                except Exception: pass
        finally: await client.aclose()
        return findings

class OpenRedirectModule(VulnModule):
    name = "open_redirect_scanner"
    category = "open_redirect"
    description = "Open redirect vulnerability detection"
    PAYLOADS = ["https://evil.com", "//evil.com", "/\\evil.com", "https://evil.com%2f%2f",
                "//evil.com@legitimate.com", "https:evil.com", "//%09/evil.com"]
    async def test(self, target: str, params: dict, auth: Any = None, hypothesis: dict | None = None) -> list[dict]:
        findings = []
        client = httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False)
        try:
            redirect_params = [p for p in (params or {}) if any(
                kw in p.lower() for kw in ["redirect", "url", "next", "return", "callback", "goto", "redir"])]
            for param in redirect_params:
                for payload in self.PAYLOADS:
                    p = dict(params or {}); p[param] = payload
                    try:
                        resp = await client.get(target, params=p)
                        location = resp.headers.get("location", "")
                        if resp.status_code in (301, 302, 303, 307, 308) and "evil.com" in location:
                            findings.append({"title": f"Open Redirect via '{param}'", "severity": "medium",
                                "category": "open_redirect", "affected_url": target, "param": param,
                                "confidence": 0.9, "evidence": {"payload": payload, "redirect_to": location},
                                "source_tool": self.name, "description": f"Open redirect to: {location}"})
                            break
                    except Exception: pass
        finally: await client.aclose()
        return findings

class CORSModule(VulnModule):
    name = "cors_scanner"
    category = "cors_misconfig"
    description = "CORS misconfiguration testing"
    async def test(self, target: str, params: dict, auth: Any = None, hypothesis: dict | None = None) -> list[dict]:
        findings = []
        client = httpx.AsyncClient(timeout=15.0, verify=False)
        try:
            origins = ["https://evil.com", "null", f"https://{target.split('/')[2]}.evil.com"]
            for origin in origins:
                resp = await client.get(target, headers={"Origin": origin})
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")
                if acao == origin or (acao == "*" and acac.lower() == "true"):
                    findings.append({"title": f"CORS reflects origin: {origin}", "severity": "high",
                        "category": "cors_misconfig", "affected_url": target, "confidence": 0.9,
                        "evidence": {"origin": origin, "acao": acao, "acac": acac},
                        "source_tool": self.name, "description": f"CORS misconfiguration allows {origin}"})
        except Exception: pass
        finally: await client.aclose()
        return findings

class APISecurityModule(VulnModule):
    name = "api_security_scanner"
    category = "api_security"
    description = "API security testing — Swagger/OpenAPI exposure, method enumeration"
    API_PATHS = ["/swagger.json", "/openapi.json", "/api-docs", "/swagger-ui.html",
                 "/v1/swagger.json", "/api/swagger", "/.well-known/openapi.json"]
    async def test(self, target: str, params: dict, auth: Any = None, hypothesis: dict | None = None) -> list[dict]:
        findings = []
        from urllib.parse import urlparse
        base = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
        client = httpx.AsyncClient(timeout=10.0, verify=False)
        try:
            for path in self.API_PATHS:
                try:
                    resp = await client.get(f"{base}{path}")
                    if resp.status_code == 200 and any(kw in resp.text.lower() for kw in ["swagger", "openapi", "paths"]):
                        findings.append({"title": f"API documentation exposed: {path}", "severity": "low",
                            "category": "api_security", "affected_url": f"{base}{path}", "confidence": 0.95,
                            "evidence": {"path": path, "size": len(resp.text)}, "source_tool": self.name,
                            "description": f"API documentation publicly accessible at {path}"})
                except Exception: pass
        finally: await client.aclose()
        return findings

class DataExposureModule(VulnModule):
    name = "data_exposure_scanner"
    category = "data_exposure"
    description = "Sensitive data exposure detection"
    SENSITIVE_PATHS = ["/.env", "/.git/config", "/wp-config.php", "/config.php", "/.DS_Store",
                        "/backup.sql", "/database.sql", "/.htpasswd", "/server-status", "/debug/vars",
                        "/actuator/env", "/actuator/health", "/.well-known/security.txt"]
    async def test(self, target: str, params: dict, auth: Any = None, hypothesis: dict | None = None) -> list[dict]:
        findings = []
        from urllib.parse import urlparse
        base = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
        client = httpx.AsyncClient(timeout=10.0, verify=False)
        try:
            for path in self.SENSITIVE_PATHS:
                try:
                    resp = await client.get(f"{base}{path}")
                    if resp.status_code == 200 and len(resp.text) > 10:
                        sev = "critical" if any(kw in path for kw in [".env", ".git", "config", "backup"]) else "medium"
                        findings.append({"title": f"Sensitive file exposed: {path}", "severity": sev,
                            "category": "data_exposure", "affected_url": f"{base}{path}", "confidence": 0.85,
                            "evidence": {"path": path, "size": len(resp.text), "preview": resp.text[:200]},
                            "source_tool": self.name, "description": f"Sensitive file accessible: {path}"})
                except Exception: pass
        finally: await client.aclose()
        return findings

class MisconfigModule(VulnModule):
    name = "misconfig_scanner"
    category = "misconfiguration"
    description = "Server and application misconfiguration detection"
    async def test(self, target: str, params: dict, auth: Any = None, hypothesis: dict | None = None) -> list[dict]:
        findings = []
        client = httpx.AsyncClient(timeout=10.0, verify=False)
        try:
            resp = await client.options(target)
            allow = resp.headers.get("allow", "")
            if "TRACE" in allow or "TRACK" in allow:
                findings.append({"title": "HTTP TRACE/TRACK method enabled", "severity": "low",
                    "category": "misconfiguration", "affected_url": target, "confidence": 0.9,
                    "evidence": {"allow_header": allow}, "source_tool": self.name,
                    "description": "Dangerous HTTP methods enabled"})
            # Directory listing
            resp = await client.get(target)
            if any(kw in resp.text.lower() for kw in ["index of /", "directory listing", "<pre>", "parent directory"]):
                findings.append({"title": "Directory listing enabled", "severity": "low",
                    "category": "misconfiguration", "affected_url": target, "confidence": 0.9,
                    "evidence": {"indicator": "directory listing detected"}, "source_tool": self.name,
                    "description": "Server directory listing is enabled"})
        except Exception: pass
        finally: await client.aclose()
        return findings

class CloudExposureModule(VulnModule):
    name = "cloud_exposure_scanner"
    category = "cloud_exposure"
    description = "Cloud storage and service exposure detection"
    async def test(self, target: str, params: dict, auth: Any = None, hypothesis: dict | None = None) -> list[dict]:
        findings = []
        from urllib.parse import urlparse
        domain = urlparse(target).netloc
        client = httpx.AsyncClient(timeout=10.0, verify=False)
        try:
            # S3 bucket check
            bucket_names = [domain.split(".")[0], domain.replace(".", "-"), f"{domain.split('.')[0]}-assets",
                            f"{domain.split('.')[0]}-backup", f"{domain.split('.')[0]}-data"]
            for bucket in bucket_names:
                try:
                    resp = await client.get(f"https://{bucket}.s3.amazonaws.com")
                    if resp.status_code == 200 and "ListBucketResult" in resp.text:
                        findings.append({"title": f"Public S3 bucket: {bucket}", "severity": "critical",
                            "category": "cloud_exposure", "affected_url": f"https://{bucket}.s3.amazonaws.com",
                            "confidence": 0.95, "evidence": {"bucket": bucket, "listing": True},
                            "source_tool": self.name, "description": f"S3 bucket '{bucket}' is publicly listable"})
                except Exception: pass
            # Azure blob check
            for name in bucket_names[:2]:
                try:
                    resp = await client.get(f"https://{name}.blob.core.windows.net/?comp=list")
                    if resp.status_code == 200:
                        findings.append({"title": f"Public Azure blob: {name}", "severity": "high",
                            "category": "cloud_exposure", "affected_url": f"https://{name}.blob.core.windows.net",
                            "confidence": 0.9, "evidence": {"container": name}, "source_tool": self.name,
                            "description": f"Azure blob '{name}' is publicly accessible"})
                except Exception: pass
        finally: await client.aclose()
        return findings
