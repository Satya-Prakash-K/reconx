"""AI engine routes — summaries, attack paths, semantic search."""

from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, Query
from reconx_shared.security.rbac import get_current_user

import structlog

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post("/summarize/{workspace_id}")
async def generate_summary(workspace_id: uuid.UUID, current_user: dict = Depends(get_current_user)):
    """Generate AI recon summary for a workspace."""
    # TODO: Call AI engine gRPC service
    return {"status": "queued", "workspace_id": str(workspace_id),
            "message": "AI summary generation queued"}


@router.get("/attack-paths/{workspace_id}")
async def get_attack_paths(workspace_id: uuid.UUID, current_user: dict = Depends(get_current_user)):
    """Get AI-generated attack path suggestions."""
    from reconx_shared.db.neo4j import Neo4jManager
    neo4j = Neo4jManager()
    try:
        paths = await neo4j.get_attack_paths(str(workspace_id))
        return {"workspace_id": str(workspace_id), "attack_paths": paths}
    except Exception as e:
        logger.warning("Attack path query failed", error=str(e))
        return {"workspace_id": str(workspace_id), "attack_paths": []}


@router.get("/semantic-search")
async def semantic_search(
    q: str = Query(..., min_length=2),
    workspace_id: str | None = None,
    limit: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
):
    """Semantic search over findings using Qdrant vector similarity."""
    # TODO: Connect to Qdrant via AI engine
    return {"query": q, "results": [],
            "message": "Semantic search via Qdrant — connect AI engine"}


@router.post("/classify/{workspace_id}")
async def classify_attack_surface(workspace_id: uuid.UUID, current_user: dict = Depends(get_current_user)):
    """AI classification of the attack surface."""
    return {"status": "queued", "workspace_id": str(workspace_id),
            "message": "Attack surface classification queued"}


@router.post("/prioritize/{workspace_id}")
async def prioritize_assets(workspace_id: uuid.UUID, current_user: dict = Depends(get_current_user)):
    """AI-based high-value asset prioritization."""
    return {"status": "queued", "workspace_id": str(workspace_id),
            "message": "Asset prioritization queued"}
