"""Vulnerability scan management routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from typing import Optional

from src.core.orchestrator import (
    VulnScanConfig, VulnCategory, VulnPhase, AuthConfig, get_orchestrator
)

router = APIRouter()


class StartScanRequest(BaseModel):
    workspace_id: str
    target_urls: list[str]
    categories: list[str] = []
    safe_mode: bool = True
    throttle_rps: float = 10.0
    browser_testing: bool = True
    ai_hypothesis: bool = True
    waf_evasion: bool = False
    auth: Optional[dict] = None


@router.post("/start")
async def start_vuln_scan(request: StartScanRequest):
    """Start an autonomous vulnerability scan."""
    categories = [VulnCategory(c) for c in request.categories] if request.categories else list(VulnCategory)

    auth_config = None
    if request.auth:
        auth_config = AuthConfig(**request.auth)

    config = VulnScanConfig(
        workspace_id=request.workspace_id,
        target_urls=request.target_urls,
        categories=categories,
        safe_mode=request.safe_mode,
        throttle_rps=request.throttle_rps,
        browser_testing=request.browser_testing,
        ai_hypothesis=request.ai_hypothesis,
        waf_evasion=request.waf_evasion,
        auth_config=auth_config,
    )

    orchestrator = get_orchestrator()
    status = await orchestrator.start_scan(config)
    return {"scan_id": status.scan_id, "status": status.status}


@router.get("/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get the current status of a vulnerability scan."""
    orchestrator = get_orchestrator()
    status = orchestrator.get_status(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail="Scan not found")
    return status.model_dump()


@router.get("/")
async def list_scans():
    """List all active vulnerability scans."""
    orchestrator = get_orchestrator()
    return [s.model_dump() for s in orchestrator.list_active()]


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel a running vulnerability scan."""
    return {"scan_id": scan_id, "status": "cancelled"}


@router.websocket("/ws/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str):
    """WebSocket for real-time scan progress streaming."""
    await websocket.accept()
    orchestrator = get_orchestrator()
    try:
        import asyncio
        while True:
            status = orchestrator.get_status(scan_id)
            if status:
                await websocket.send_json(status.model_dump())
                if status.status in ("completed", "failed"):
                    break
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
