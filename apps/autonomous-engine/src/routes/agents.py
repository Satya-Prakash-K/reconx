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


import uuid
import asyncio
import structlog

_logger = structlog.get_logger(__name__)

async def _run_with_logging(workspace_id: str, session_id: str, targets: list, max_cycles: int):
    """Wrapper that logs exceptions from the background scan task."""
    try:
        _logger.info("Background scan task started", session_id=session_id, targets=targets)
        from src.agents.graph import run_autonomous_session
        result = await run_autonomous_session(workspace_id, session_id, targets, max_cycles)
        _logger.info("Background scan task complete", session_id=session_id,
                     findings=len(result.get("findings", [])))
    except Exception as exc:
        _logger.error("Background scan task FAILED", session_id=session_id, error=str(exc), exc_info=True)

@router.post("/session/start")
async def start_session(request: SessionRequest):
    """Start an autonomous agent swarm session."""
    session_id = str(uuid.uuid4())

    # Run in background so the UI doesn't block and can connect to WebSocket
    asyncio.create_task(
        _run_with_logging(request.workspace_id, session_id, request.targets, request.max_cycles)
    )

    return {
        "session_id": session_id,
        "phase": "initializing",
        "cycle": 0,
        "findings": 0,
        "hypotheses": 0,
        "reasoning_chain": ["[system] Autonomous engine received request. Launching agents..."],
        "metrics": {},
    }


@router.get("/session/{session_id}")
async def get_session(session_id: str):
    """Get session status and results."""
    return {"session_id": session_id, "status": "complete"}


@router.get("/reasoning/{session_id}")
async def get_reasoning(session_id: str):
    """Get AI reasoning chain for a session."""
    return {"session_id": session_id, "reasoning_chain": []}
