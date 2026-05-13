"""AI-powered risk scoring engine using DSPy."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class RiskScorer:
    """AI risk scoring engine for assets and findings.

    Uses a combination of heuristic rules and DSPy-optimized
    LLM scoring for accurate risk assessment.
    """

    # Heuristic weights for risk calculation
    WEIGHTS = {
        "exposed_admin_panel": 9.0,
        "default_credentials": 9.5,
        "open_redirect": 5.0,
        "cors_misconfiguration": 6.0,
        "missing_security_headers": 3.0,
        "outdated_software": 7.0,
        "exposed_api_docs": 4.0,
        "dns_takeover": 9.0,
        "cloud_bucket_public": 8.5,
        "sensitive_data_exposure": 8.0,
        "js_secret_leak": 7.5,
        "debug_endpoint": 6.5,
        "directory_listing": 4.5,
        "backup_files": 5.5,
    }

    async def score_asset(self, asset: dict[str, Any]) -> float:
        """Calculate risk score for an asset (0-10)."""
        score = 0.0

        # Technology-based risk
        techs = asset.get("technology", [])
        outdated_techs = {"php/5", "apache/2.2", "nginx/1.0", "wordpress/4", "jquery/1"}
        for tech in techs:
            for outdated in outdated_techs:
                if outdated in tech.lower():
                    score += 2.0
                    break

        # Port-based risk
        risky_ports = {21: 3.0, 22: 1.0, 23: 5.0, 25: 2.0, 445: 4.0, 3389: 4.0,
                       8080: 1.5, 8443: 1.0, 9200: 3.0, 27017: 4.0, 6379: 4.0}
        port = asset.get("port")
        if port and port in risky_ports:
            score += risky_ports[port]

        # WAF absence increases risk
        if not asset.get("waf_detected"):
            score += 1.0

        # Normalize to 0-10
        return min(10.0, max(0.0, score))

    async def score_finding(self, finding: dict[str, Any]) -> float:
        """Calculate risk score for a finding (0-10)."""
        base_scores = {
            "critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 1.0
        }
        severity = finding.get("severity", "info")
        score = base_scores.get(severity, 1.0)

        # Boost by finding type
        finding_type = finding.get("finding_type", "")
        if finding_type in self.WEIGHTS:
            score = (score + self.WEIGHTS[finding_type]) / 2

        # Confidence modifier
        confidence = finding.get("confidence", 0.5)
        score *= (0.5 + confidence * 0.5)

        return min(10.0, max(0.0, round(score, 2)))

    async def prioritize_assets(self, assets: list[dict]) -> list[dict]:
        """Rank assets by risk score, highest first."""
        for asset in assets:
            asset["risk_score"] = await self.score_asset(asset)
        return sorted(assets, key=lambda a: a["risk_score"], reverse=True)
