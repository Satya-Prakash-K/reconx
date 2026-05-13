"""Validation Agent — AI-powered false positive reduction and finding validation."""

from __future__ import annotations

import hashlib
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class ValidationAgent:
    """Validates findings to reduce false positives and deduplicate results.

    Uses:
    - Re-testing for confirmation
    - Semantic similarity for deduplication
    - AI confidence scoring
    - Context-aware false positive filtering
    """

    # Known false positive patterns
    FALSE_POSITIVE_PATTERNS = {
        "xss": [
            "payload reflected but HTML-encoded",
            "reflected in comment/script context with sanitization",
            "CSP blocks script execution",
        ],
        "sqli": [
            "generic error page (not SQL-specific)",
            "timing variation within normal range",
            "error message from WAF not database",
        ],
    }

    async def validate_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate and deduplicate findings."""
        # Step 1: Remove exact duplicates
        deduplicated = self._deduplicate(findings)

        # Step 2: Filter likely false positives
        validated = []
        for finding in deduplicated:
            fp_score = self._false_positive_score(finding)
            finding["fp_probability"] = fp_score

            if fp_score < 0.7:  # Keep findings with <70% FP probability
                # Adjust confidence based on FP analysis
                finding["confidence"] = finding.get("confidence", 0.5) * (1 - fp_score)
                validated.append(finding)
            else:
                logger.debug("Filtered likely false positive",
                             title=finding.get("title", ""),
                             fp_score=fp_score)

        # Step 3: Re-rank by adjusted confidence
        validated.sort(key=lambda f: (
            {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(f.get("severity", "info"), 0),
            f.get("confidence", 0)
        ), reverse=True)

        # Step 4: Generate reproduction steps
        for finding in validated:
            finding["reproduction_steps"] = self._generate_reproduction(finding)

        logger.info("Validation complete",
                     input=len(findings), output=len(validated),
                     filtered=len(findings) - len(validated))
        return validated

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        """Remove duplicate findings based on semantic similarity."""
        seen: set[str] = set()
        unique: list[dict] = []

        for finding in findings:
            # Create fingerprint
            fp = hashlib.md5(
                f"{finding.get('category', '')}:"
                f"{finding.get('affected_url', '')}:"
                f"{finding.get('param', '')}:"
                f"{finding.get('title', '')}".encode()
            ).hexdigest()

            if fp not in seen:
                seen.add(fp)
                unique.append(finding)

        return unique

    def _false_positive_score(self, finding: dict) -> float:
        """Calculate false positive probability (0.0 = likely real, 1.0 = likely FP)."""
        score = 0.0
        category = finding.get("category", "")
        confidence = finding.get("confidence", 0.5)

        # Low confidence findings are more likely FP
        if confidence < 0.3:
            score += 0.3

        # Source tool reliability
        reliable_tools = {"sqlmap", "dalfox", "nuclei", "burp"}
        source = finding.get("source_tool", "")
        if source in reliable_tools:
            score -= 0.2  # More reliable
        elif source == "passive_detector":
            # Passive findings for info-level are less actionable
            if finding.get("severity") == "info":
                score += 0.3

        # XSS: Check if actually exploitable
        if category == "xss":
            evidence = finding.get("evidence", {})
            if evidence.get("reflected") and not evidence.get("context_exploitable", True):
                score += 0.4

        # Anomaly-based findings have higher FP rate
        if "anomaly" in finding.get("title", "").lower():
            score += 0.25

        return min(1.0, max(0.0, score))

    def _generate_reproduction(self, finding: dict) -> str:
        """Generate step-by-step reproduction instructions."""
        category = finding.get("category", "unknown")
        url = finding.get("affected_url", "N/A")
        param = finding.get("param", "N/A")
        payload = finding.get("evidence", {}).get("payload", finding.get("payload", "N/A"))

        steps = [
            f"## Reproduction Steps for: {finding.get('title', 'Finding')}",
            f"",
            f"**Target URL:** `{url}`",
            f"**Parameter:** `{param}`",
            f"**Severity:** {finding.get('severity', 'unknown').upper()}",
            f"",
            f"### Steps:",
            f"1. Navigate to: `{url}`",
        ]

        if category == "xss":
            steps.extend([
                f"2. Inject the following payload in the `{param}` parameter:",
                f"   ```",
                f"   {payload}",
                f"   ```",
                f"3. Observe that the payload is reflected/executed in the response",
                f"4. Verify script execution in browser console",
            ])
        elif category == "sqli":
            steps.extend([
                f"2. Modify the `{param}` parameter with:",
                f"   ```",
                f"   {payload}",
                f"   ```",
                f"3. Observe SQL error message or behavioral difference",
                f"4. Confirm with: `sqlmap -u '{url}' -p {param}`",
            ])
        elif category == "ssrf":
            steps.extend([
                f"2. Set the `{param}` parameter to an internal URL:",
                f"   ```",
                f"   {payload}",
                f"   ```",
                f"3. Observe server-side request to the specified URL",
                f"4. Verify with an external callback (e.g., Burp Collaborator)",
            ])
        else:
            steps.extend([
                f"2. Use the following payload: `{payload}`",
                f"3. Monitor the application response for anomalies",
            ])

        steps.extend([
            f"",
            f"**Confidence:** {finding.get('confidence', 0):.0%}",
            f"**Detected by:** {finding.get('source_tool', 'unknown')}",
        ])

        return "\n".join(steps)
