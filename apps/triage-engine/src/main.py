"""ReconX Triage Engine — AI-powered vulnerability triage, exploit intelligence & reporting."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import structlog

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle — initialize AI models and connections."""
    logger.info("Starting Triage Engine")

    # Pre-load embedding model
    try:
        from src.ai.embeddings import EmbeddingPipeline
        pipeline = EmbeddingPipeline()
        await pipeline.init()
        app.state.embedding_pipeline = pipeline
        logger.info("Embedding pipeline loaded")
    except Exception as e:
        logger.warning("Embedding pipeline not available", error=str(e))

    # Connect Neo4j knowledge graph
    try:
        from src.knowledge.graph import KnowledgeGraph
        kg = KnowledgeGraph()
        await kg.init()
        app.state.knowledge_graph = kg
        logger.info("Knowledge graph connected")
    except Exception as e:
        logger.warning("Knowledge graph not available", error=str(e))

    yield

    logger.info("Triage Engine shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title="ReconX Triage Engine",
        description="AI vulnerability triage, exploit intelligence & report generation",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from src.routes import triage, reports, knowledge, intelligence
    app.include_router(triage.router, prefix="/api/v1/triage", tags=["Triage"])
    app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
    app.include_router(knowledge.router, prefix="/api/v1/knowledge", tags=["Knowledge"])
    app.include_router(intelligence.router, prefix="/api/v1/intel", tags=["Intelligence"])

    @app.get("/health")
    async def health():
        return {"status": "healthy", "service": "reconx-triage-engine"}

    return app


app = create_app()
