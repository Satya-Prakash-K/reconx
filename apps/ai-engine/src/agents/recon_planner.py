"""Autonomous recon planning agent using LangGraph."""

from __future__ import annotations

from typing import Any, TypedDict

import structlog

logger = structlog.get_logger(__name__)


class ReconState(TypedDict):
    """State for the recon planning agent."""
    workspace_id: str
    targets: list[str]
    completed_phases: list[str]
    current_phase: str
    findings_count: int
    assets_count: int
    risk_assessment: str
    next_actions: list[str]
    ai_reasoning: str


class ReconPlannerAgent:
    """LangGraph-based autonomous recon planning agent.

    Plans and coordinates reconnaissance phases based on:
    - Target scope and asset types
    - Previous phase results
    - AI risk assessment
    - Attack surface analysis
    """

    def __init__(self):
        from src.llm import get_llm_gateway
        self.llm = get_llm_gateway()

    async def plan_recon(self, state: ReconState) -> ReconState:
        """Generate an AI-driven recon plan based on current state."""
        prompt = f"""You are an expert bug bounty recon planner. Based on the current state,
determine the optimal next recon phases to execute.

Current State:
- Targets: {', '.join(state['targets'])}
- Completed Phases: {', '.join(state['completed_phases'])}
- Assets Found: {state['assets_count']}
- Findings: {state['findings_count']}

Available Phases:
1. subdomain_enumeration - Discover subdomains
2. dns_analysis - DNS records, takeover detection
3. http_probing - HTTP status, tech stack, WAF
4. port_scanning - Open ports and services
5. url_collection - URLs from archives and crawling
6. js_analysis - JavaScript secrets and endpoints
7. visual_recon - Screenshots and visual comparison
8. cloud_exposure - S3/Azure/GCP bucket detection
9. api_discovery - GraphQL, Swagger, API endpoints

Return a JSON object with:
- "next_phases": ordered list of phase names to execute next
- "reasoning": brief explanation of strategy
- "priority_targets": any high-priority targets to focus on
- "risk_assessment": overall risk level (low/medium/high/critical)
"""

        try:
            response = await self.llm.generate(prompt)
            import json
            plan = json.loads(response)
            state["next_actions"] = plan.get("next_phases", [])
            state["risk_assessment"] = plan.get("risk_assessment", "medium")
            state["ai_reasoning"] = plan.get("reasoning", "")
        except Exception as e:
            logger.warning("AI planning failed, using default phases", error=str(e))
            state["next_actions"] = ["subdomain_enumeration", "dns_analysis", "http_probing"]
            state["risk_assessment"] = "medium"
            state["ai_reasoning"] = "Fallback to default recon pipeline"

        return state

    async def generate_summary(self, workspace_id: str, findings: list[dict]) -> str:
        """Generate an AI summary of recon findings."""
        findings_text = "\n".join(
            f"- [{f.get('severity', 'info')}] {f.get('title', 'Unknown')}: {f.get('description', '')[:200]}"
            for f in findings[:50]
        )

        prompt = f"""Generate a concise executive summary of the following bug bounty reconnaissance findings.
Include: key risks, high-value targets, recommended next steps.

Findings:
{findings_text}

Format as markdown with sections: ## Executive Summary, ## Key Findings, ## Risk Assessment, ## Recommendations
"""

        try:
            return await self.llm.generate(prompt)
        except Exception as e:
            logger.error("Summary generation failed", error=str(e))
            return f"# Recon Summary\n\nFound {len(findings)} findings. AI summary unavailable."
