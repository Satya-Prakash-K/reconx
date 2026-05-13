"""ReconX API Gateway — FastAPI application entry point."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.config import settings
from src.routes import programs, scans, findings, workspaces, auth, ai, health
from src.middleware.audit import AuditMiddleware
from src.middleware.rate_limit import setup_rate_limiting

from reconx_shared.db.postgres import init_db, close_db
from reconx_shared.db.elasticsearch import ElasticsearchManager
from reconx_shared.db.neo4j import Neo4jManager
from reconx_shared.telemetry import init_telemetry

import structlog

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle — startup and shutdown."""
    logger.info("Starting ReconX API Gateway", env=settings.ENV)

    # Initialize telemetry
    if settings.ENV != "test":
        init_telemetry("reconx-api-gateway")

    # Initialize databases
    await init_db()

    # Initialize Elasticsearch indices
    es = ElasticsearchManager()
    try:
        await es.ensure_indices()
    except Exception as e:
        logger.warning("Elasticsearch not available", error=str(e))

    # Initialize Neo4j schema
    neo4j = Neo4jManager()
    try:
        await neo4j.init_schema()
    except Exception as e:
        logger.warning("Neo4j not available", error=str(e))

    logger.info("API Gateway ready", port=settings.API_PORT)

    yield

    # Shutdown
    await close_db()
    try:
        await es.close()
        await neo4j.close()
    except Exception:
        pass
    logger.info("API Gateway shutdown complete")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="ReconX API",
        description="AI-Powered Autonomous Bug Bounty Reconnaissance Platform",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS
    origins = settings.CORS_ORIGINS.split(",") if settings.CORS_ORIGINS else ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Audit logging middleware
    app.add_middleware(AuditMiddleware)

    # Rate limiting
    setup_rate_limiting(app)

    # Routes
    app.include_router(health.router, tags=["Health"])
    app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
    app.include_router(programs.router, prefix="/api/v1/programs", tags=["Programs"])
    app.include_router(workspaces.router, prefix="/api/v1/workspaces", tags=["Workspaces"])
    app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
    app.include_router(findings.router, prefix="/api/v1/findings", tags=["Findings"])
    app.include_router(ai.router, prefix="/api/v1/ai", tags=["AI"])

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.ENV == "development",
        workers=settings.API_WORKERS if settings.ENV == "production" else 1,
    )
