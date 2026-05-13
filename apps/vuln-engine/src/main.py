"""ReconX Vulnerability Engine — Main FastAPI application."""

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
    """Application lifecycle."""
    logger.info("Starting Vulnerability Engine")

    # Initialize Ray cluster connection
    try:
        import ray
        ray_addr = os.getenv("RAY_ADDRESS", "auto")
        if not ray.is_initialized():
            ray.init(address=ray_addr, ignore_reinit_error=True)
            logger.info("Ray cluster connected", address=ray_addr)
    except Exception as e:
        logger.warning("Ray not available — running in local mode", error=str(e))

    # Install Playwright browsers on first run
    try:
        from playwright.async_api import async_playwright
        logger.info("Playwright available")
    except Exception as e:
        logger.warning("Playwright not available", error=str(e))

    yield

    logger.info("Vulnerability Engine shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title="ReconX Vulnerability Engine",
        description="Autonomous vulnerability analysis and intelligent fuzzing",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from src.routes import vuln_scans, vuln_findings, fuzzing, agents
    app.include_router(vuln_scans.router, prefix="/api/v1/vuln/scans", tags=["Vuln Scans"])
    app.include_router(vuln_findings.router, prefix="/api/v1/vuln/findings", tags=["Vuln Findings"])
    app.include_router(fuzzing.router, prefix="/api/v1/fuzzing", tags=["Fuzzing"])
    app.include_router(agents.router, prefix="/api/v1/agents", tags=["AI Agents"])

    @app.get("/health")
    async def health():
        return {"status": "healthy", "service": "reconx-vuln-engine"}

    return app


app = create_app()
