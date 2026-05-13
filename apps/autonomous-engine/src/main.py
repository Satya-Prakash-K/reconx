"""ReconX Autonomous Engine — next-gen AI security operations."""

from __future__ import annotations
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import structlog

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Autonomous Engine starting")
    yield
    logger.info("Autonomous Engine shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title="ReconX Autonomous Engine",
        description="Next-gen AI-assisted autonomous security operations",
        version="2.0.0",
        lifespan=lifespan,
    )
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

    from src.routes import agents, monitoring, analysis, browser, workflows
    app.include_router(agents.router, prefix="/api/v1/agents", tags=["Agents"])
    app.include_router(monitoring.router, prefix="/api/v1/monitor", tags=["Monitoring"])
    app.include_router(analysis.router, prefix="/api/v1/analysis", tags=["Analysis"])
    app.include_router(browser.router, prefix="/api/v1/browser", tags=["Browser"])
    app.include_router(workflows.router, prefix="/api/v1/workflows", tags=["Workflows"])

    @app.get("/health")
    async def health():
        return {"status": "healthy", "service": "reconx-autonomous-engine", "version": "2.0.0"}

    return app


app = create_app()
