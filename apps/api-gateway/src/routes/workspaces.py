"""Workspace management routes."""

from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text

from reconx_shared.models.scope import Workspace, WorkspaceCreate
from reconx_shared.security.rbac import get_current_user
from reconx_shared.db.postgres import get_db_session

import structlog

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post("/", response_model=Workspace, status_code=status.HTTP_201_CREATED)
async def create_workspace(data: WorkspaceCreate, current_user: dict = Depends(get_current_user)):
    """Create an isolated workspace for a target program."""
    workspace_id = uuid.uuid4()
    async with get_db_session() as session:
        # Verify program exists
        prog = await session.execute(
            text("SELECT id FROM programs WHERE id = :id AND is_active = true"),
            {"id": str(data.program_id)},
        )
        if not prog.fetchone():
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Program not found")

        await session.execute(
            text("""
                INSERT INTO workspaces (id, program_id, name, description, created_by)
                VALUES (:id, :pid, :name, :desc, :uid)
            """),
            {
                "id": str(workspace_id), "pid": str(data.program_id),
                "name": data.name, "desc": data.description,
                "uid": current_user["sub"],
            },
        )

    logger.info("Workspace created", workspace_id=str(workspace_id))
    return Workspace(id=workspace_id, program_id=data.program_id, name=data.name, description=data.description)


@router.get("/", response_model=list[Workspace])
async def list_workspaces(program_id: uuid.UUID | None = None, current_user: dict = Depends(get_current_user)):
    """List workspaces, optionally filtered by program."""
    async with get_db_session() as session:
        if program_id:
            result = await session.execute(
                text("SELECT * FROM workspaces WHERE program_id = :pid AND is_active = true ORDER BY updated_at DESC"),
                {"pid": str(program_id)},
            )
        else:
            result = await session.execute(
                text("SELECT * FROM workspaces WHERE is_active = true ORDER BY updated_at DESC LIMIT 100"),
            )
        return [
            Workspace(
                id=r.id, program_id=r.program_id, name=r.name, description=r.description,
                scan_count=r.scan_count, finding_count=r.finding_count, asset_count=r.asset_count,
                created_at=r.created_at, updated_at=r.updated_at,
            )
            for r in result.fetchall()
        ]


@router.get("/{workspace_id}", response_model=Workspace)
async def get_workspace(workspace_id: uuid.UUID, current_user: dict = Depends(get_current_user)):
    """Get workspace details."""
    async with get_db_session() as session:
        result = await session.execute(
            text("SELECT * FROM workspaces WHERE id = :id"), {"id": str(workspace_id)},
        )
        row = result.fetchone()
        if not row:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")
        return Workspace(
            id=row.id, program_id=row.program_id, name=row.name, description=row.description,
            scan_count=row.scan_count, finding_count=row.finding_count, asset_count=row.asset_count,
            created_at=row.created_at, updated_at=row.updated_at,
        )
