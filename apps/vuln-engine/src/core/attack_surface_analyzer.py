"""Attack Surface Analyzer — processes recon data to identify testable endpoints."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse, parse_qs

import httpx
import structlog

logger = structlog.get_logger(__name__)


class EndpointInfo:
    """Parsed endpoint with parameters and metadata."""

    def __init__(self, url: str, method: str = "GET", params: dict | None = None,
                 headers: dict | None = None, body: dict | None = None,
                 content_type: str | None = None, auth_required: bool = False):
        self.url = url
        self.method = method
        self.params = params or {}
        self.headers = headers or {}
        self.body = body or {}
        self.content_type = content_type
        self.auth_required = auth_required
        self.technologies: list[str] = []
        self.risk_indicators: list[str] = []
        self.priority_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "url": self.url, "method": self.method,
            "params": self.params, "headers": self.headers,
            "body": self.body, "content_type": self.content_type,
            "auth_required": self.auth_required,
            "technologies": self.technologies,
            "risk_indicators": self.risk_indicators,
            "priority_score": self.priority_score,
        }


class AttackSurfaceAnalyzer:
    """Analyzes recon data to build a prioritized list of testable endpoints."""

    # Parameter names that indicate high-value targets
    HIGH_RISK_PARAMS = {
        "url", "redirect", "next", "return", "callback", "redir", "goto",  # Open redirect
        "id", "uid", "user_id", "account", "profile", "order",  # IDOR
        "query", "search", "q", "s", "keyword", "filter",  # SQLi
        "file", "path", "page", "template", "include", "doc",  # LFI/RFI
        "target", "host", "dest", "uri", "domain",  # SSRF
        "cmd", "exec", "command", "ping", "ip",  # Command injection
        "token", "jwt", "session", "auth",  # Auth
        "upload", "attachment", "image",  # File upload
    }

    async def analyze(self, workspace_id: str, target_urls: list[str]) -> dict[str, Any]:
        """Analyze targets and return prioritized endpoint list."""
        endpoints: list[EndpointInfo] = []

        # Fetch URLs from the recon database
        try:
            from reconx_shared.db.postgres import get_db_session
            from sqlalchemy import text
            async with get_db_session() as session:
                # Get URLs from recon phase
                result = await session.execute(
                    text("SELECT url, domain, parameters FROM urls WHERE workspace_id = :wid LIMIT 5000"),
                    {"wid": workspace_id},
                )
                for row in result.fetchall():
                    ep = self._parse_url(row.url)
                    endpoints.append(ep)

                # Get HTTP probes
                result = await session.execute(
                    text("SELECT url, technologies, status_code FROM http_probes WHERE workspace_id = :wid"),
                    {"wid": workspace_id},
                )
                for row in result.fetchall():
                    ep = self._parse_url(row.url)
                    if row.technologies:
                        ep.technologies = list(row.technologies)
                    endpoints.append(ep)

                # Get API endpoints from JS analysis
                result = await session.execute(
                    text("SELECT value, finding_type FROM js_findings WHERE workspace_id = :wid AND finding_type = 'endpoint'"),
                    {"wid": workspace_id},
                )
                for row in result.fetchall():
                    ep = self._parse_url(row.value)
                    ep.risk_indicators.append("js_discovered")
                    endpoints.append(ep)
        except Exception as e:
            logger.warning("Database fetch failed, using provided URLs", error=str(e))

        # Add explicitly provided targets
        for url in target_urls:
            endpoints.append(self._parse_url(url))

        # Deduplicate
        seen = set()
        unique: list[EndpointInfo] = []
        for ep in endpoints:
            key = f"{ep.method}:{ep.url}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)

        # Score and prioritize
        for ep in unique:
            ep.priority_score = self._calculate_priority(ep)

        # Sort by priority (highest first)
        unique.sort(key=lambda e: e.priority_score, reverse=True)

        logger.info("Attack surface analyzed",
                     total=len(unique),
                     high_priority=sum(1 for e in unique if e.priority_score >= 7.0))

        return {
            "total_endpoints": len(unique),
            "endpoints": [e.to_dict() for e in unique],
            "high_priority": sum(1 for e in unique if e.priority_score >= 7.0),
            "parameter_count": sum(len(e.params) for e in unique),
            "technologies": list({t for e in unique for t in e.technologies}),
        }

    def _parse_url(self, url: str) -> EndpointInfo:
        """Parse a URL into an EndpointInfo with extracted parameters."""
        parsed = urlparse(url)
        params = {}
        for key, values in parse_qs(parsed.query).items():
            params[key] = values[0] if values else ""

        return EndpointInfo(
            url=f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else url,
            params=params,
        )

    def _calculate_priority(self, ep: EndpointInfo) -> float:
        """Calculate priority score (0-10) based on attack surface indicators."""
        score = 0.0

        # High-risk parameter names
        for param in ep.params:
            if param.lower() in self.HIGH_RISK_PARAMS:
                score += 2.0
                ep.risk_indicators.append(f"high_risk_param:{param}")

        # Number of parameters (more = more attack surface)
        score += min(3.0, len(ep.params) * 0.5)

        # API endpoints score higher
        path = urlparse(ep.url).path.lower()
        if any(seg in path for seg in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
            score += 2.0
            ep.risk_indicators.append("api_endpoint")

        # Admin/dashboard paths
        if any(seg in path for seg in ["/admin", "/dashboard", "/manage", "/config", "/debug"]):
            score += 3.0
            ep.risk_indicators.append("admin_path")

        # Upload/file paths
        if any(seg in path for seg in ["/upload", "/import", "/file", "/attachment"]):
            score += 2.0
            ep.risk_indicators.append("file_handling")

        # Auth-related paths
        if any(seg in path for seg in ["/login", "/auth", "/oauth", "/token", "/register", "/reset"]):
            score += 2.0
            ep.risk_indicators.append("auth_endpoint")

        # JS-discovered endpoints (likely hidden/internal)
        if "js_discovered" in ep.risk_indicators:
            score += 1.5

        return min(10.0, score)
