"""Findings routes — search, list, update findings."""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text

from reconx_shared.models.findings import Finding, FindingCreate, FindingSeverity, FindingStatus
from reconx_shared.security.rbac import get_current_user
from reconx_shared.db.postgres import get_db_session
from reconx_shared.db.elasticsearch import ElasticsearchManager

import structlog

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.get("/", response_model=list[Finding])
async def list_findings(
    workspace_id: Optional[uuid.UUID] = None,
    severity: Optional[FindingSeverity] = None,
    status_filter: Optional[FindingStatus] = None,
    limit: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
):
    """List findings with filtering."""
    conditions = []
    params: dict = {"limit": limit}
    if workspace_id:
        conditions.append("workspace_id = :wid")
        params["wid"] = str(workspace_id)
    if severity:
        conditions.append("severity = :sev")
        params["sev"] = severity.value
    if status_filter:
        conditions.append("status = :st")
        params["st"] = status_filter.value

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    async with get_db_session() as session:
        result = await session.execute(
            text(f"SELECT * FROM findings {where} ORDER BY risk_score DESC LIMIT :limit"), params)
        return [Finding(
            id=r.id, workspace_id=r.workspace_id, title=r.title,
            description=r.description, severity=FindingSeverity(r.severity),
            status=FindingStatus(r.status), finding_type=r.finding_type,
            risk_score=r.risk_score or 0, confidence=r.confidence or 0,
            source_tool=r.source_tool, ai_summary=r.ai_summary,
            created_at=r.created_at,
        ) for r in result.fetchall()]


@router.get("/search")
async def search_findings(
    q: str = Query(..., min_length=2),
    workspace_id: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """Full-text search across findings using Elasticsearch."""
    es = ElasticsearchManager()
    try:
        results = await es.search_findings(q, workspace_id, severity)
        return results
    except Exception as e:
        logger.warning("ES search failed, falling back to PostgreSQL", error=str(e))
        # Fallback to PostgreSQL LIKE search
        async with get_db_session() as session:
            result = await session.execute(
                text("SELECT * FROM findings WHERE title ILIKE :q OR description ILIKE :q LIMIT 50"),
                {"q": f"%{q}%"})
            return [{"id": str(r.id), "title": r.title, "severity": r.severity} for r in result.fetchall()]


@router.patch("/{finding_id}/status")
async def update_finding_status(
    finding_id: uuid.UUID,
    new_status: FindingStatus,
    current_user: dict = Depends(get_current_user),
):
    """Update the status of a finding."""
    async with get_db_session() as session:
        result = await session.execute(
            text("UPDATE findings SET status = :s WHERE id = :id RETURNING id"),
            {"s": new_status.value, "id": str(finding_id)})
        if not result.fetchone():
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return {"finding_id": str(finding_id), "status": new_status.value}
