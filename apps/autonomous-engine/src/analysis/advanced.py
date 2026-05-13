"""Advanced Security Analysis — OAuth, CI/CD, K8s exposure, secret leakage, API analysis.

Specialized modules for next-gen attack surface analysis that go beyond
traditional vulnerability scanning.
"""

from __future__ import annotations

import re
from typing import Any
import httpx
import structlog

logger = structlog.get_logger(__name__)


class OAuthFlowAnalyzer:
    """Analyzes OAuth/OIDC implementations for security weaknesses."""

    OAUTH_ISSUES = [
        ("open_redirect_in_redirect_uri", "redirect_uri accepts arbitrary domains"),
        ("state_missing", "No CSRF state parameter in auth request"),
        ("pkce_missing", "No PKCE code_challenge in public client"),
        ("token_in_url", "Access token exposed in URL fragment"),
        ("insecure_redirect", "redirect_uri uses HTTP instead of HTTPS"),
    ]

    async def analyze(self, auth_url: str, client_id: str = "") -> list[dict]:
        findings = []
        async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=False) as client:
            # Test open redirect in redirect_uri
            for evil_uri in ["https://evil.com/callback", "https://evil.com%40legit.com", "//evil.com"]:
                try:
                    resp = await client.get(auth_url, params={
                        "client_id": client_id, "redirect_uri": evil_uri,
                        "response_type": "code", "scope": "openid",
                    })
                    if resp.status_code in (302, 301) and "evil.com" in resp.headers.get("location", ""):
                        findings.append({
                            "title": "OAuth open redirect in redirect_uri",
                            "severity": "high", "category": "open_redirect",
                            "affected_url": auth_url,
                            "evidence": {"redirect_uri": evil_uri, "location": resp.headers.get("location", "")},
                            "confidence": 0.9, "source_tool": "oauth_analyzer",
                        })
                        break
                except Exception:
                    pass

            # Check for missing state parameter acceptance
            try:
                resp = await client.get(auth_url, params={
                    "client_id": client_id, "redirect_uri": f"{auth_url.split('/')[0]}//{auth_url.split('/')[2]}/callback",
                    "response_type": "code", "scope": "openid",
                })
                if resp.status_code in (200, 302) and "state" not in str(resp.url):
                    findings.append({
                        "title": "OAuth flow accepts requests without state parameter",
                        "severity": "medium", "category": "auth_flaw",
                        "affected_url": auth_url, "confidence": 0.7,
                        "source_tool": "oauth_analyzer",
                    })
            except Exception:
                pass
        return findings


class CICDExposureAnalyzer:
    """Discovers exposed CI/CD configurations and artifacts."""

    CI_CD_PATHS = [
        "/.github/workflows/", "/.gitlab-ci.yml", "/Jenkinsfile", "/.circleci/config.yml",
        "/.travis.yml", "/azure-pipelines.yml", "/bitbucket-pipelines.yml",
        "/.drone.yml", "/.buildkite/pipeline.yml", "/Dockerfile", "/docker-compose.yml",
        "/.env", "/.env.production", "/.env.local", "/.env.staging",
        "/deploy.sh", "/Makefile", "/Procfile", "/terraform/", "/k8s/",
    ]

    async def scan(self, base_url: str) -> list[dict]:
        findings = []
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            for path in self.CI_CD_PATHS:
                try:
                    resp = await client.get(f"{base_url.rstrip('/')}{path}")
                    if resp.status_code == 200 and len(resp.text) > 10:
                        severity = "critical" if ".env" in path else "high" if "secret" in resp.text.lower() else "medium"
                        findings.append({
                            "title": f"CI/CD artifact exposed: {path}",
                            "severity": severity, "category": "data_exposure",
                            "affected_url": f"{base_url}{path}", "confidence": 0.9,
                            "evidence": {"path": path, "size": len(resp.text), "preview": resp.text[:200]},
                            "source_tool": "cicd_analyzer",
                        })
                except Exception:
                    pass
        return findings


class KubernetesExposureAnalyzer:
    """Detects exposed Kubernetes resources and misconfigurations."""

    K8S_PATHS = [
        "/api/v1/namespaces", "/api/v1/pods", "/api/v1/secrets", "/api/v1/services",
        "/apis", "/version", "/healthz", "/metrics", "/debug/pprof/",
        "/.well-known/openid-configuration",
    ]
    K8S_PORTS = [6443, 8443, 10250, 10255, 2379, 8080, 9090]

    async def scan(self, base_url: str) -> list[dict]:
        findings = []
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            for path in self.K8S_PATHS:
                try:
                    resp = await client.get(f"{base_url.rstrip('/')}{path}")
                    if resp.status_code == 200 and ("kind" in resp.text or "apiVersion" in resp.text):
                        findings.append({
                            "title": f"Kubernetes API exposed: {path}",
                            "severity": "critical" if "secrets" in path else "high",
                            "category": "misconfiguration",
                            "affected_url": f"{base_url}{path}", "confidence": 0.95,
                            "evidence": {"preview": resp.text[:300]},
                            "source_tool": "k8s_analyzer",
                        })
                except Exception:
                    pass
        return findings


class SecretLeakageIntelligence:
    """Detects leaked secrets in responses, headers, and source code."""

    SECRET_PATTERNS = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "critical"),
        (r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}", "GitHub Token", "critical"),
        (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key", "critical"),
        (r"xox[bpors]-[0-9a-zA-Z-]{10,}", "Slack Token", "critical"),
        (r"sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}", "Square Token", "high"),
        (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "SendGrid API Key", "critical"),
        (r"key-[0-9a-zA-Z]{32}", "Mailgun API Key", "high"),
        (r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "Private Key", "critical"),
        (r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}", "Hardcoded Password", "high"),
        (r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"][^'\"]{16,}", "API Key", "high"),
        (r"Bearer\s+[a-zA-Z0-9\-._~+/]{20,}", "Bearer Token", "high"),
    ]

    async def scan_content(self, url: str, content: str) -> list[dict]:
        findings = []
        for pattern, name, severity in self.SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                for match in matches[:3]:
                    masked = match[:8] + "..." + match[-4:] if len(match) > 12 else "***"
                    findings.append({
                        "title": f"Secret leakage: {name}",
                        "severity": severity, "category": "data_exposure",
                        "affected_url": url, "confidence": 0.9,
                        "evidence": {"type": name, "masked_value": masked, "pattern": pattern},
                        "source_tool": "secret_scanner",
                    })
        return findings

    async def scan_url(self, url: str) -> list[dict]:
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                resp = await client.get(url)
                return await self.scan_content(url, resp.text)
        except Exception:
            return []


class RESTAPIAnalyzer:
    """Analyzes REST API structure and relationships."""

    SPEC_PATHS = ["/swagger.json", "/openapi.json", "/api-docs", "/swagger/v1/swagger.json",
                  "/v1/swagger.json", "/v2/api-docs", "/v3/api-docs"]

    async def discover_spec(self, base_url: str) -> dict | None:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            for path in self.SPEC_PATHS:
                try:
                    resp = await client.get(f"{base_url.rstrip('/')}{path}")
                    if resp.status_code == 200 and ("swagger" in resp.text.lower() or "openapi" in resp.text.lower()):
                        return {"url": f"{base_url}{path}", "spec": resp.json()}
                except Exception:
                    pass
        return None

    async def analyze_spec(self, base_url: str) -> list[dict]:
        findings = []
        spec_result = await self.discover_spec(base_url)
        if not spec_result:
            return findings

        spec = spec_result["spec"]
        findings.append({
            "title": "API specification publicly accessible",
            "severity": "medium", "category": "api_security",
            "affected_url": spec_result["url"], "confidence": 0.95,
            "source_tool": "api_analyzer",
        })

        # Check for auth-less endpoints
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() in ("GET", "POST", "PUT", "DELETE"):
                    security = details.get("security", spec.get("security", []))
                    if not security:
                        findings.append({
                            "title": f"Unauthenticated {method.upper()} {path}",
                            "severity": "high" if method.upper() in ("POST", "PUT", "DELETE") else "medium",
                            "category": "auth_flaw",
                            "affected_url": f"{base_url}{path}",
                            "confidence": 0.7, "source_tool": "api_analyzer",
                        })
        return findings
