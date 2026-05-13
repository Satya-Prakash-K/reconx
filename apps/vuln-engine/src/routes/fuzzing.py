"""Fuzzing API routes."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class FuzzRequest(BaseModel):
    url: str
    params: dict[str, str] = {}
    categories: list[str] = ["xss", "sqli", "ssrf"]
    max_payloads: int = 50
    waf_evasion: bool = False


@router.post("/start")
async def start_fuzzing(request: FuzzRequest):
    """Start intelligent fuzzing on a specific endpoint."""
    from src.fuzzing.engine import FuzzingEngine
    engine = FuzzingEngine()
    endpoint = {
        "url": request.url,
        "params": request.params,
        "priority_score": 10.0,
    }
    findings = await engine.fuzz(
        endpoints=[endpoint],
        hypotheses=[],
        config=None,
    )
    return {"findings": findings, "total": len(findings)}


@router.get("/payloads/{category}")
async def list_payloads(category: str):
    """List available payloads for a category."""
    from src.fuzzing.engine import PayloadGenerator
    gen = PayloadGenerator()
    payloads = gen.PAYLOADS.get(category, [])
    return {"category": category, "payloads": payloads, "count": len(payloads)}
