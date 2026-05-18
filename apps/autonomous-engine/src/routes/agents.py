"""Agent swarm API routes — with direct WebSocket streaming."""

from __future__ import annotations
import asyncio
import uuid
from typing import Any

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

router = APIRouter()
_logger = structlog.get_logger(__name__)

# ── In-memory session store ─────────────────────────────────────────────────
# Maps session_id → latest state snapshot for REST polling
_sessions: dict[str, dict[str, Any]] = {}
# Maps session_id → list of connected WebSocket clients
_ws_clients: dict[str, list[WebSocket]] = {}


class SessionRequest(BaseModel):
    workspace_id: str
    targets: list[str]
    max_cycles: int = 3
    mode: str = "autonomous"


# ── Broadcast helper ────────────────────────────────────────────────────────

async def _broadcast(session_id: str, state: dict[str, Any]) -> None:
    """Push state snapshot to all connected WebSocket clients for a session."""
    _sessions[session_id] = state
    dead = []
    for ws in _ws_clients.get(session_id, []):
        try:
            await ws.send_json(state)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients[session_id].remove(ws)


# ── Background scan with streaming ─────────────────────────────────────────

async def _run_scan(workspace_id: str, session_id: str, targets: list[str], max_cycles: int) -> None:
    """Run the swarm and broadcast progress directly to connected WebSockets."""
    try:
        _logger.info("Scan task started", session_id=session_id, targets=targets)

        from src.agents.swarm import (
            create_initial_state, PlannerAgent, ReconAgent, AnalysisAgent,
            HypothesisAgent, RiskAgent, MemoryAgent,
        )

        state = create_initial_state(workspace_id, session_id, targets, max_cycles)

        agents_in_order = [
            ("planning",    PlannerAgent()),
            ("recon",       ReconAgent()),
            ("analysis",    AnalysisAgent()),
            ("hypothesis",  HypothesisAgent()),
            ("triage",      RiskAgent()),
            ("memory",      MemoryAgent()),
        ]

        total_steps = max_cycles * len(agents_in_order)
        step = 0

        for cycle in range(max_cycles):
            for phase, agent in agents_in_order:
                state["phase"] = phase
                state = await agent.execute(state)
                step += 1
                progress = round((step / total_steps) * 100, 1)

                snapshot = {
                    "phase": phase,
                    "progress": progress,
                    "details": {
                        "reasoning_chain": state.get("reasoning_chain", []),
                        "findings": len(state.get("findings", [])),
                        "hypotheses": len(state.get("hypotheses", [])),
                        "endpoints": len(state.get("discovered_endpoints", [])),
                        "cycle": cycle + 1,
                    }
                }
                await _broadcast(session_id, snapshot)
                await asyncio.sleep(0.3)  # Small yield so WS messages flush

        # Final complete broadcast
        final = {
            "phase": "complete",
            "progress": 100.0,
            "details": {
                "reasoning_chain": state.get("reasoning_chain", []),
                "findings": len(state.get("findings", [])),
                "hypotheses": len(state.get("hypotheses", [])),
                "endpoints": len(state.get("discovered_endpoints", [])),
                "cycle": max_cycles,
            }
        }
        await _broadcast(session_id, final)
        _logger.info("Scan complete", session_id=session_id,
                     findings=len(state.get("findings", [])),
                     endpoints=len(state.get("discovered_endpoints", [])))

    except Exception as exc:
        _logger.error("Scan task FAILED", session_id=session_id, error=str(exc), exc_info=True)
        await _broadcast(session_id, {
            "phase": "error",
            "progress": 0,
            "details": {
                "reasoning_chain": [f"[error] Scan failed: {exc}"],
                "findings": 0, "hypotheses": 0, "endpoints": 0, "cycle": 0
            }
        })


# ── REST endpoint: start session ────────────────────────────────────────────

@router.post("/session/start")
async def start_session(request: SessionRequest):
    """Start an autonomous agent swarm session."""
    session_id = str(uuid.uuid4())
    _sessions[session_id] = {
        "phase": "initializing", "progress": 0,
        "details": {
            "reasoning_chain": ["[system] Autonomous engine received request. Launching agents..."],
            "findings": 0, "hypotheses": 0, "endpoints": 0, "cycle": 0,
        }
    }
    _ws_clients[session_id] = []
    asyncio.create_task(_run_scan(request.workspace_id, session_id, request.targets, request.max_cycles))
    return {"session_id": session_id, "phase": "initializing"}


# ── REST endpoint: poll progress ────────────────────────────────────────────

@router.get("/session/{session_id}/progress")
async def get_session_progress(session_id: str):
    """REST polling endpoint — returns latest scan state."""
    return _sessions.get(session_id, {
        "phase": "not_found", "progress": 0,
        "details": {"reasoning_chain": [], "findings": 0, "hypotheses": 0, "endpoints": 0}
    })


# ── WebSocket: live streaming ───────────────────────────────────────────────

@router.websocket("/ws/{session_id}")
async def session_ws(websocket: WebSocket, session_id: str):
    """Direct WebSocket — streams scan progress without Redis middleware."""
    await websocket.accept()
    if session_id not in _ws_clients:
        _ws_clients[session_id] = []
    _ws_clients[session_id].append(websocket)

    # Send current state immediately on connect
    if session_id in _sessions:
        await websocket.send_json(_sessions[session_id])

    try:
        while True:
            await asyncio.sleep(1)
            # Keep alive ping
            current = _sessions.get(session_id, {})
            if current.get("phase") in ("complete", "error", "not_found"):
                break
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        if session_id in _ws_clients and websocket in _ws_clients[session_id]:
            _ws_clients[session_id].remove(websocket)
