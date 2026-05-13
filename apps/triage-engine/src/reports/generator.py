"""Report Generation Engine — multi-platform vulnerability report generator.

Generates professional reports for:
- HackerOne format
- Bugcrowd format
- Intigriti format
- CVE-style advisory
- Executive summary
- Technical writeup
- PDF export

Each report includes AI-generated:
- Title, summary, technical details
- Reproduction steps with evidence
- Impact analysis and risk scoring
- Remediation guidance
- CWE references and CVSS vectors
- Root cause analysis
- Suggested fixes
- AI proof-of-concept code
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from jinja2 import Template

import structlog

logger = structlog.get_logger(__name__)


class ReportFormat:
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    CVE = "cve"
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    MARKDOWN = "markdown"
    PDF = "pdf"


class ReportGenerator:
    """Multi-format vulnerability report generator with AI enhancement."""

    def __init__(self):
        self.llm = None
        self._init_llm()

    def _init_llm(self):
        try:
            from src.ai.llm_gateway import MultiModelGateway
            self.llm = MultiModelGateway()
        except Exception:
            pass

    async def generate(
        self,
        finding: dict[str, Any],
        format: str = ReportFormat.HACKERONE,
        workspace_id: str = "",
    ) -> dict[str, Any]:
        """Generate a report for a single finding in the specified format."""
        # Enrich with AI analysis
        enriched = await self._ai_enrich(finding)

        generators = {
            ReportFormat.HACKERONE: self._gen_hackerone,
            ReportFormat.BUGCROWD: self._gen_bugcrowd,
            ReportFormat.INTIGRITI: self._gen_intigriti,
            ReportFormat.CVE: self._gen_cve,
            ReportFormat.EXECUTIVE: self._gen_executive,
            ReportFormat.TECHNICAL: self._gen_technical,
            ReportFormat.MARKDOWN: self._gen_markdown,
        }

        gen_fn = generators.get(format, self._gen_markdown)
        report = await gen_fn(enriched)

        report["metadata"] = {
            "format": format,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "workspace_id": workspace_id,
            "finding_id": finding.get("id", ""),
        }

        return report

    async def generate_batch(
        self,
        findings: list[dict],
        format: str = ReportFormat.EXECUTIVE,
        workspace_id: str = "",
    ) -> dict[str, Any]:
        """Generate a batch report for multiple findings."""
        reports = []
        for f in findings:
            r = await self.generate(f, format, workspace_id)
            reports.append(r)

        executive = await self._gen_batch_executive(findings)
        return {
            "executive_summary": executive,
            "reports": reports,
            "total_findings": len(findings),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _ai_enrich(self, finding: dict) -> dict:
        """Enrich finding with AI-generated content."""
        enriched = dict(finding)

        if self.llm:
            try:
                # Root cause analysis
                enriched["root_cause"] = await self.llm.generate(
                    f"Explain the root cause of this vulnerability in 2-3 sentences:\n"
                    f"Type: {finding.get('category', '')}\n"
                    f"Title: {finding.get('title', '')}\n"
                    f"URL: {finding.get('affected_url', '')}\n"
                    f"Description: {finding.get('description', '')}",
                    max_tokens=200, temperature=0.3,
                )

                # Suggested fix
                enriched["suggested_fix"] = await self.llm.generate(
                    f"Provide a concise code-level fix for this vulnerability:\n"
                    f"Type: {finding.get('category', '')}\n"
                    f"Description: {finding.get('description', '')}",
                    max_tokens=300, temperature=0.3,
                )

                # Impact explanation
                enriched["impact_explanation"] = await self.llm.generate(
                    f"Explain the business and security impact of this {finding.get('category', '')} "
                    f"vulnerability at {finding.get('affected_url', '')} in 3-4 sentences for a "
                    f"non-technical audience.",
                    max_tokens=200, temperature=0.4,
                )
            except Exception as e:
                logger.debug("AI enrichment failed", error=str(e))

        # Fallback enrichments
        if "root_cause" not in enriched:
            enriched["root_cause"] = self._heuristic_root_cause(finding)
        if "suggested_fix" not in enriched:
            enriched["suggested_fix"] = self._heuristic_fix(finding)
        if "impact_explanation" not in enriched:
            enriched["impact_explanation"] = self._heuristic_impact(finding)

        return enriched

    # ── Platform-specific generators ─────────

    async def _gen_hackerone(self, f: dict) -> dict:
        """Generate HackerOne-format report."""
        severity = f.get("severity", "medium")
        cvss = f.get("cvss_vector", "N/A")
        repro = self._build_reproduction(f)

        report = Template("""## Summary
{{ title }}

## Severity
**{{ severity | upper }}** (CVSS: {{ cvss_score }})
CVSS Vector: `{{ cvss_vector }}`

## Description
{{ description }}

{{ root_cause }}

## Steps to Reproduce
{{ reproduction_steps }}

## Supporting Material/References
- CWE: {{ cwe_id }} - {{ cwe_name }}
- OWASP: {{ owasp_category }}
- Affected URL: `{{ affected_url }}`
{% if param %}- Parameter: `{{ param }}`{% endif %}

## Impact
{{ impact_explanation }}

## Remediation
{{ suggested_fix }}
""").render(**f, reproduction_steps=repro)

        return {"format": "hackerone", "content": report, "title": f.get("title", "")}

    async def _gen_bugcrowd(self, f: dict) -> dict:
        """Generate Bugcrowd-format report."""
        repro = self._build_reproduction(f)
        report = Template("""# {{ title }}

## Vulnerability Type
{{ category | upper }} ({{ cwe_id }})

## URL / Location
`{{ affected_url }}`{% if param %} — Parameter: `{{ param }}`{% endif %}

## Severity
{{ severity | upper }} — CVSS {{ cvss_score }} (`{{ cvss_vector }}`)

## Description
{{ description }}

**Root Cause:** {{ root_cause }}

## Proof of Concept
{{ reproduction_steps }}

## Business Impact
{{ impact_explanation }}

## Suggested Remediation
{{ suggested_fix }}

## References
- CWE: {{ cwe_id }} - {{ cwe_name }}
- OWASP: {{ owasp_category }}
""").render(**f, reproduction_steps=repro)

        return {"format": "bugcrowd", "content": report, "title": f.get("title", "")}

    async def _gen_intigriti(self, f: dict) -> dict:
        """Generate Intigriti-format report."""
        repro = self._build_reproduction(f)
        report = Template("""## Vulnerability Report

**Title:** {{ title }}
**Type:** {{ category | upper }}
**Severity:** {{ severity | upper }}
**CVSS Score:** {{ cvss_score }} (`{{ cvss_vector }}`)

### Domain / URL
`{{ affected_url }}`

### Summary
{{ description }}

### Steps to Reproduce
{{ reproduction_steps }}

### Impact
{{ impact_explanation }}

### Root Cause
{{ root_cause }}

### Remediation Advice
{{ suggested_fix }}

### References
- {{ cwe_id }}: {{ cwe_name }}
- {{ owasp_category }}
""").render(**f, reproduction_steps=repro)

        return {"format": "intigriti", "content": report, "title": f.get("title", "")}

    async def _gen_cve(self, f: dict) -> dict:
        """Generate CVE-style advisory."""
        report = Template("""# Security Advisory

## Title
{{ title }}

## CVE ID
CVE-YYYY-XXXXX (Pending Assignment)

## CVSS Score
{{ cvss_score }} ({{ severity | upper }})
Vector: `{{ cvss_vector }}`

## CWE Classification
{{ cwe_id }}: {{ cwe_name }}

## Affected Component
- URL: `{{ affected_url }}`
{% if param %}- Parameter: `{{ param }}`{% endif %}
- Tool: {{ source_tool }}

## Description
{{ description }}

## Root Cause
{{ root_cause }}

## Impact
{{ impact_explanation }}

## Remediation
{{ suggested_fix }}

## Timeline
- Discovered: {{ triaged_at | default('N/A') }}
- Reported: Pending
- Fixed: Pending
- Disclosed: Pending

## Credit
Discovered by ReconX automated security assessment.
""").render(**f)

        return {"format": "cve", "content": report, "title": f.get("title", "")}

    async def _gen_executive(self, f: dict) -> dict:
        """Generate non-technical executive summary."""
        report = Template("""# Executive Summary: {{ title }}

**Risk Level:** {{ severity | upper }}
**CVSS Score:** {{ cvss_score }}/10

## What Was Found
{{ impact_explanation }}

## Business Risk
{% if severity == "critical" %}This is a **critical** vulnerability that could lead to complete compromise of sensitive data and systems. Immediate action is required.
{% elif severity == "high" %}This is a **high-severity** issue that poses significant risk to data confidentiality and system integrity.
{% elif severity == "medium" %}This is a **moderate** risk that should be addressed in the near term to maintain security posture.
{% else %}This is a **low-risk** finding that should be addressed as part of regular security maintenance.{% endif %}

## Recommended Action
{{ suggested_fix }}

## Affected System
`{{ affected_url }}`
""").render(**f)

        return {"format": "executive", "content": report, "title": f.get("title", "")}

    async def _gen_technical(self, f: dict) -> dict:
        """Generate detailed technical writeup."""
        repro = self._build_reproduction(f)
        evidence = json.dumps(f.get("evidence", {}), indent=2)

        report = Template("""# Technical Writeup: {{ title }}

## Classification
| Field | Value |
|-------|-------|
| Category | {{ category | upper }} |
| CWE | {{ cwe_id }} - {{ cwe_name }} |
| OWASP | {{ owasp_category }} |
| CVSS | {{ cvss_score }} (`{{ cvss_vector }}`) |
| Severity | {{ severity | upper }} |
| Exploitability | {{ exploitability_score }}/10 |
| Impact | {{ impact_score }}/10 |
| Confidence | {{ confidence | default(0) | round(2) }} |

## Affected Endpoint
- **URL:** `{{ affected_url }}`
{% if param %}- **Parameter:** `{{ param }}`{% endif %}
- **Detection Tool:** {{ source_tool }}

## Description
{{ description }}

## Root Cause Analysis
{{ root_cause }}

## Reproduction Steps
{{ reproduction_steps }}

## Evidence
```json
{{ evidence }}
```

## Impact Analysis
{{ impact_explanation }}

## Remediation
{{ suggested_fix }}
""").render(**f, reproduction_steps=repro, evidence=evidence)

        return {"format": "technical", "content": report, "title": f.get("title", "")}

    async def _gen_markdown(self, f: dict) -> dict:
        return await self._gen_technical(f)

    async def _gen_batch_executive(self, findings: list[dict]) -> str:
        """Generate executive summary for a batch of findings."""
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1

        total = len(findings)
        risk = "CRITICAL" if sev_counts["critical"] > 0 else "HIGH" if sev_counts["high"] > 0 else "MEDIUM"

        return (
            f"# Security Assessment Executive Summary\n\n"
            f"**Overall Risk:** {risk}\n"
            f"**Total Findings:** {total}\n\n"
            f"| Severity | Count |\n|----------|-------|\n"
            + "\n".join(f"| {s.upper()} | {c} |" for s, c in sev_counts.items() if c > 0)
            + f"\n\nImmediate attention required for {sev_counts['critical']} critical and "
            f"{sev_counts['high']} high-severity findings."
        )

    # ── Helper methods ───────────────────────

    def _build_reproduction(self, f: dict) -> str:
        """Build step-by-step reproduction from finding data."""
        if f.get("reproduction_steps"):
            return f["reproduction_steps"]

        steps = [f"1. Navigate to `{f.get('affected_url', 'N/A')}`"]
        evidence = f.get("evidence", {})
        payload = evidence.get("payload", f.get("payload", ""))

        if payload:
            param = f.get("param", "parameter")
            steps.append(f"2. Insert the following payload in the `{param}` field:\n   ```\n   {payload}\n   ```")
            steps.append("3. Submit the request and observe the response")
            steps.append("4. Verify the vulnerability based on the behavioral change described above")
        else:
            steps.append("2. Observe the response headers and body")
            steps.append("3. Note the security misconfiguration described in the finding")

        return "\n".join(steps)

    def _heuristic_root_cause(self, f: dict) -> str:
        causes = {
            "xss": "User input is not properly sanitized or output-encoded before being rendered in HTML context.",
            "sqli": "User input is concatenated into SQL queries without parameterization or proper escaping.",
            "ssrf": "Server-side requests are made using user-controlled URLs without allowlist validation.",
            "idor": "Resource access relies on user-supplied identifiers without server-side authorization checks.",
            "auth_flaw": "Authentication mechanisms lack sufficient controls such as rate limiting or MFA.",
            "authz_bypass": "Authorization checks are implemented client-side or can be bypassed via header manipulation.",
            "jwt_weakness": "JWT tokens use weak signing algorithms or secrets, enabling token forgery.",
            "cors_misconfig": "CORS policy reflects arbitrary origins without validation.",
            "data_exposure": "Sensitive files or configuration data are accessible without authentication.",
        }
        return causes.get(f.get("category", ""), "Insufficient input validation or access control.")

    def _heuristic_fix(self, f: dict) -> str:
        fixes = {
            "xss": "Implement context-aware output encoding. Use a Content Security Policy (CSP) header. Sanitize all user input using a trusted library.",
            "sqli": "Use parameterized queries (prepared statements). Never concatenate user input into SQL. Implement an ORM layer.",
            "ssrf": "Implement URL allowlisting. Block requests to internal/private IP ranges. Validate URL schemes.",
            "idor": "Implement server-side authorization checks for every resource access. Use indirect references (UUIDs).",
            "auth_flaw": "Implement rate limiting, account lockout, and multi-factor authentication.",
            "authz_bypass": "Implement server-side authorization at the middleware level. Never rely on client-side checks.",
            "jwt_weakness": "Use strong signing algorithms (RS256/ES256). Rotate secrets regularly. Set token expiration.",
            "cors_misconfig": "Configure CORS with an explicit origin allowlist. Never reflect arbitrary origins.",
            "data_exposure": "Remove sensitive files from web roots. Implement proper access controls. Use .gitignore.",
        }
        return fixes.get(f.get("category", ""), "Implement proper input validation and access control mechanisms.")

    def _heuristic_impact(self, f: dict) -> str:
        impacts = {
            "xss": "An attacker could execute arbitrary JavaScript in users' browsers, potentially stealing session tokens, credentials, or performing actions on behalf of authenticated users.",
            "sqli": "An attacker could extract, modify, or delete all data in the database, potentially compromising user credentials, payment information, and business data.",
            "ssrf": "An attacker could access internal services, cloud metadata, and potentially pivot to internal network resources.",
            "idor": "An attacker could access, modify, or delete other users' data by manipulating resource identifiers.",
            "auth_flaw": "An attacker could gain unauthorized access to user accounts through credential stuffing or brute force attacks.",
        }
        return impacts.get(f.get("category", ""), "This vulnerability could be exploited to compromise the security of the application and its users.")
