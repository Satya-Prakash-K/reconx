"""Knowledge graph API routes — exploit intelligence queries."""

from __future__ import annotations
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


@router.get("/similar/{category}")
async def find_similar(category: str, limit: int = 10):
    """Find historically similar findings."""
    from src.knowledge.graph import KnowledgeGraph
    kg = KnowledgeGraph()
    await kg.init()
    results = await kg.find_similar_findings(category, limit=limit)
    await kg.close()
    return {"findings": results}


@router.get("/payloads/{category}")
async def get_payloads(category: str, waf: str = ""):
    """Get historically effective payloads."""
    from src.knowledge.graph import KnowledgeGraph
    kg = KnowledgeGraph()
    await kg.init()
    results = await kg.get_effective_payloads(category, waf)
    await kg.close()
    return {"payloads": results}


@router.get("/chains/{workspace_id}")
async def get_attack_chains(workspace_id: str):
    """Get vulnerability chains in a workspace."""
    from src.knowledge.graph import KnowledgeGraph
    kg = KnowledgeGraph()
    await kg.init()
    results = await kg.get_attack_chains(workspace_id)
    await kg.close()
    return {"chains": results}


@router.get("/cross-intel/{category}")
async def cross_program_intel(category: str):
    """Get cross-program intelligence."""
    from src.knowledge.graph import KnowledgeGraph
    kg = KnowledgeGraph()
    await kg.init()
    results = await kg.get_cross_program_intel(category)
    await kg.close()
    return {"intelligence": results}


@router.post("/store")
async def store_finding(finding: dict):
    """Store a finding in the knowledge graph."""
    from src.knowledge.graph import KnowledgeGraph
    kg = KnowledgeGraph()
    await kg.init()
    await kg.store_finding(finding)
    await kg.close()
    return {"status": "stored"}
