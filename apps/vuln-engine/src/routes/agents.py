"""AI Agent routes."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class HypothesisRequest(BaseModel):
    workspace_id: str
    endpoints: list[dict] = []


@router.post("/hypotheses")
async def generate_hypotheses(request: HypothesisRequest):
    """Generate AI vulnerability hypotheses for endpoints."""
    from src.agents.hypothesis_agent import VulnHypothesisAgent
    agent = VulnHypothesisAgent()
    hypotheses = await agent.generate_hypotheses(
        {"endpoints": request.endpoints},
        categories=[],
    )
    return {"hypotheses": hypotheses, "count": len(hypotheses)}


@router.post("/classify")
async def classify_endpoints(request: HypothesisRequest):
    """Classify endpoints by function and risk."""
    from src.agents.classifier_agent import EndpointClassifierAgent
    agent = EndpointClassifierAgent()
    result = await agent.classify_endpoints(request.workspace_id, request.endpoints)
    return result


@router.post("/report/{scan_id}")
async def generate_report(scan_id: str, workspace_id: str = ""):
    """Generate AI vulnerability report for a scan."""
    from src.agents.reporting_agent import ReportingAgent
    agent = ReportingAgent()
    report = await agent.generate_report(scan_id, workspace_id, [])
    return report


@router.get("/reasoning/{scan_id}")
async def get_ai_reasoning(scan_id: str):
    """Get AI reasoning chain for a scan."""
    from src.core.orchestrator import get_orchestrator
    orchestrator = get_orchestrator()
    status = orchestrator.get_status(scan_id)
    if status:
        return {"reasoning": status.ai_reasoning}
    return {"reasoning": []}
