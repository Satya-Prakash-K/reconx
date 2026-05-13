"""Monitoring API routes."""

from __future__ import annotations
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class MonitorRequest(BaseModel):
    urls: list[str]


class JSAnalysisRequest(BaseModel):
    url: str
    old_content: str = ""
    new_content: str = ""


@router.post("/check")
async def check_changes(request: MonitorRequest):
    """Check for changes across URLs."""
    from src.monitoring.change_detector import ChangeDetector
    detector = ChangeDetector()
    changes = await detector.scan_batch(request.urls)
    return {"changes": changes, "urls_checked": len(request.urls)}


@router.post("/js-diff")
async def analyze_js(request: JSAnalysisRequest):
    """Analyze JavaScript file changes."""
    from src.monitoring.change_detector import JSDiffAnalyzer
    analyzer = JSDiffAnalyzer()
    findings = await analyzer.analyze_js_diff(request.url, request.old_content, request.new_content)
    return {"findings": findings}


@router.post("/dns-drift")
async def check_dns(domain: str):
    """Check DNS drift."""
    from src.monitoring.change_detector import InfrastructureDriftDetector
    detector = InfrastructureDriftDetector()
    result = await detector.check_dns_drift(domain)
    return result
