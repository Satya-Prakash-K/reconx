"""Scan management routes."""

from __future__ import annotations

import json
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status, WebSocket
from sqlalchemy import text

from reconx_shared.models.scans import Scan, ScanCreate, ScanStatus
from reconx_shared.security.rbac import get_current_user
from reconx_shared.db.postgres import get_db_session
from reconx_shared.db.redis import RedisManager

import structlog

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post("/", response_model=Scan, status_code=status.HTTP_201_CREATED)
async def create_scan(data: ScanCreate, current_user: dict = Depends(get_current_user)):
    """Create and queue a new recon scan."""
    scan_id = uuid.uuid4()
    async with get_db_session() as session:
        ws = await session.execute(
            text("SELECT id FROM workspaces WHERE id = :id AND is_active = true"),
            {"id": str(data.workspace_id)},
        )
        if not ws.fetchone():
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")

        await session.execute(
            text("""INSERT INTO scans (id, workspace_id, name, description, status, config)
                    VALUES (:id, :wid, :name, :desc, 'queued', :config)"""),
            {"id": str(scan_id), "wid": str(data.workspace_id),
             "name": data.name or f"Scan-{str(scan_id)[:8]}",
             "desc": data.description, "config": json.dumps(data.config.model_dump())},
        )
        await session.execute(
            text("UPDATE workspaces SET scan_count = scan_count + 1 WHERE id = :id"),
            {"id": str(data.workspace_id)},
        )

    logger.info("Scan queued", scan_id=str(scan_id))
    return Scan(id=scan_id, workspace_id=data.workspace_id,
                name=data.name, status=ScanStatus.QUEUED, config=data.config)


@router.get("/", response_model=list[Scan])
async def list_scans(
    workspace_id: Optional[uuid.UUID] = None,
    limit: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
):
    """List scans."""
    params: dict = {"limit": limit}
    where = ""
    if workspace_id:
        where = "WHERE workspace_id = :wid"
        params["wid"] = str(workspace_id)

    async with get_db_session() as session:
        result = await session.execute(
            text(f"SELECT * FROM scans {where} ORDER BY created_at DESC LIMIT :limit"), params)
        return [Scan(id=r.id, workspace_id=r.workspace_id, name=r.name,
                     status=ScanStatus(r.status), progress_percent=r.progress_percent or 0,
                     total_assets_found=r.total_assets_found or 0,
                     created_at=r.created_at) for r in result.fetchall()]


@router.post("/{scan_id}/cancel", status_code=200)
async def cancel_scan(scan_id: uuid.UUID, current_user: dict = Depends(get_current_user)):
    """Cancel a running scan."""
    async with get_db_session() as session:
        await session.execute(
            text("UPDATE scans SET status = 'cancelled' WHERE id = :id AND status IN ('running','queued')"),
            {"id": str(scan_id)})
    return {"message": "Scan cancelled"}


@router.websocket("/ws/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str):
    """WebSocket for real-time scan progress."""
    await websocket.accept()
    redis_mgr = RedisManager()
    import asyncio
    try:
        while True:
            progress = await redis_mgr.get_scan_progress(scan_id)
            if progress:
                await websocket.send_json(progress)
                if progress.get("progress", 0) >= 100:
                    break
            await asyncio.sleep(2)
    except Exception:
        pass
    finally:
        await websocket.close()
