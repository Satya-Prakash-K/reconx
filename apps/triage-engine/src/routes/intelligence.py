"""Intelligence API routes — RAG queries and exploit intelligence."""

from __future__ import annotations
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class RAGQueryRequest(BaseModel):
    question: str
    context: dict = {}


class ExploitIntelRequest(BaseModel):
    category: str
    url: str = ""


@router.post("/query")
async def rag_query(request: RAGQueryRequest):
    """Query the RAG pipeline with a security question."""
    from src.ai.rag_pipeline import RAGPipeline
    rag = RAGPipeline()
    await rag.init()
    result = await rag.query(request.question, request.context)
    return result


@router.post("/exploit-intel")
async def get_exploit_intel(request: ExploitIntelRequest):
    """Get exploit intelligence for a vulnerability category."""
    from src.ai.rag_pipeline import RAGPipeline
    rag = RAGPipeline()
    await rag.init()
    result = await rag.get_exploit_intel(request.category, request.url)
    return result


@router.post("/correlate")
async def correlate_finding(finding: dict):
    """Find semantically correlated findings across workspaces."""
    from src.ai.embeddings import EmbeddingPipeline, SemanticCorrelationEngine
    pipeline = EmbeddingPipeline()
    await pipeline.init()
    engine = SemanticCorrelationEngine(pipeline)
    results = await engine.correlate(finding)
    return {"correlations": results}
