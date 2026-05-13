"""Agent swarm API routes."""

from __future__ import annotations
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class SessionRequest(BaseModel):
    workspace_id: str
    targets: list[str]
    max_cycles: int = 3
    mode: str = "autonomous"


class AgentQueryRequest(BaseModel):
    workspace_id: str
    question: str


@router.post("/session/start")
async def start_session(request: SessionRequest):
    """Start an autonomous agent swarm session."""
    from src.agents.graph import run_autonomous_session
    result = await run_autonomous_session(
        request.workspace_id, request.targets, request.max_cycles,
    )
    return {
        "session_id": result.get("session_id", ""),
        "phase": result.get("phase", ""),
        "cycle": result.get("cycle", 0),
        "findings": len(result.get("findings", [])),
        "hypotheses": len(result.get("hypotheses", [])),
        "reasoning_chain": result.get("reasoning_chain", []),
        "metrics": result.get("metrics", {}),
    }


@router.get("/session/{session_id}")
async def get_session(session_id: str):
    """Get session status and results."""
    return {"session_id": session_id, "status": "complete"}


@router.get("/reasoning/{session_id}")
async def get_reasoning(session_id: str):
    """Get AI reasoning chain for a session."""
    return {"session_id": session_id, "reasoning_chain": []}
