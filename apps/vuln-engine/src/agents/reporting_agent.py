"""Reporting Agent — AI-powered vulnerability report generation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class ReportingAgent:
    """Generates comprehensive vulnerability reports with AI analysis."""

    async def generate_report(
        self, scan_id: str, workspace_id: str, findings: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Generate a full vulnerability report."""

        # Severity breakdown
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Category breakdown
        category_counts: dict[str, int] = {}
        for f in findings:
            cat = f.get("category", "unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Generate AI executive summary
        exec_summary = await self._generate_executive_summary(findings, severity_counts)

        # Generate markdown report
        markdown = self._build_markdown_report(
            scan_id, workspace_id, findings, severity_counts, category_counts, exec_summary
        )

        # Build JSON report
        report = {
            "scan_id": scan_id,
            "workspace_id": workspace_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "executive_summary": exec_summary,
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
            "total_findings": len(findings),
            "findings": findings,
            "markdown_report": markdown,
            "risk_score": self._calculate_risk_score(severity_counts),
            "recommendations": self._generate_recommendations(findings),
        }

        logger.info("Report generated", scan_id=scan_id, findings=len(findings))
        return report

    async def _generate_executive_summary(
        self, findings: list[dict], severity_counts: dict
    ) -> str:
        """Generate AI executive summary."""
        try:
            from apps.ai_engine.src.llm import get_llm_gateway
            llm = get_llm_gateway()

            findings_text = "\n".join(
                f"- [{f.get('severity', 'info').upper()}] {f.get('title', 'Unknown')}"
                for f in findings[:30]
            )

            prompt = f"""Generate a concise executive summary of these security findings:

{findings_text}

Severity: {json.dumps(severity_counts)}

Include: overall risk level, key concerns, and top 3 priority remediation items.
Keep it under 200 words. Use professional security assessment language."""

            return await llm.generate(prompt)
        except Exception:
            # Fallback static summary
            total = len(findings)
            critical = severity_counts.get("critical", 0)
            high = severity_counts.get("high", 0)
            risk = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM"
            return (
                f"Security assessment identified {total} findings. "
                f"Risk Level: {risk}. "
                f"Critical: {critical}, High: {high}, "
                f"Medium: {severity_counts.get('medium', 0)}, "
                f"Low: {severity_counts.get('low', 0)}. "
                f"Immediate remediation recommended for critical and high severity findings."
            )

    def _build_markdown_report(self, scan_id, workspace_id, findings,
                                severity_counts, category_counts, exec_summary) -> str:
        """Build a formatted markdown report."""
        lines = [
            f"# Vulnerability Assessment Report",
            f"",
            f"**Scan ID:** `{scan_id}`",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Risk Score:** {self._calculate_risk_score(severity_counts):.1f}/10",
            f"",
            f"## Executive Summary",
            f"",
            exec_summary,
            f"",
            f"## Severity Breakdown",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                lines.append(f"| {sev.upper()} | {count} |")

        lines.extend([f"", f"## Findings", f""])

        for i, finding in enumerate(findings, 1):
            sev = finding.get("severity", "info").upper()
            lines.extend([
                f"### {i}. [{sev}] {finding.get('title', 'Finding')}",
                f"",
                f"**Category:** {finding.get('category', 'unknown')}",
                f"**URL:** `{finding.get('affected_url', 'N/A')}`",
                f"**Confidence:** {finding.get('confidence', 0):.0%}",
                f"",
                f"{finding.get('description', '')}",
                f"",
            ])

            if finding.get("reproduction_steps"):
                lines.extend([finding["reproduction_steps"], ""])

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def _calculate_risk_score(self, severity_counts: dict) -> float:
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        total_weight = sum(weights[s] * c for s, c in severity_counts.items())
        return min(10.0, total_weight / max(1, sum(severity_counts.values())))

    def _generate_recommendations(self, findings: list[dict]) -> list[str]:
        recs = set()
        for f in findings:
            cat = f.get("category", "")
            if cat == "xss":
                recs.add("Implement Content Security Policy (CSP) headers")
                recs.add("Use context-aware output encoding for all user input")
            elif cat == "sqli":
                recs.add("Use parameterized queries / prepared statements exclusively")
                recs.add("Implement input validation with allowlists")
            elif cat == "ssrf":
                recs.add("Implement URL allowlisting for server-side requests")
                recs.add("Block requests to internal IP ranges (RFC1918)")
            elif cat == "cors_misconfig":
                recs.add("Configure CORS with explicit origin allowlist")
            elif cat in ("idor", "authz_bypass"):
                recs.add("Implement server-side authorization checks on all resources")
            elif cat == "jwt_weakness":
                recs.add("Use strong JWT signing algorithms (RS256/ES256)")
        return list(recs)[:10]
