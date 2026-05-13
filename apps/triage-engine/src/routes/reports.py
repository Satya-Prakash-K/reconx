"""Report generation API routes."""

from __future__ import annotations
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


class ReportRequest(BaseModel):
    finding: dict
    format: str = "hackerone"
    workspace_id: str = ""


class BatchReportRequest(BaseModel):
    findings: list[dict]
    format: str = "executive"
    workspace_id: str = ""


@router.post("/generate")
async def generate_report(request: ReportRequest):
    """Generate a report for a single finding."""
    from src.reports.generator import ReportGenerator
    generator = ReportGenerator()
    report = await generator.generate(request.finding, request.format, request.workspace_id)
    return report


@router.post("/generate/batch")
async def generate_batch_report(request: BatchReportRequest):
    """Generate reports for multiple findings."""
    from src.reports.generator import ReportGenerator
    generator = ReportGenerator()
    report = await generator.generate_batch(request.findings, request.format, request.workspace_id)
    return report


@router.get("/formats")
async def list_formats():
    """List available report formats."""
    return {"formats": [
        {"id": "hackerone", "name": "HackerOne", "description": "HackerOne bug bounty report format"},
        {"id": "bugcrowd", "name": "Bugcrowd", "description": "Bugcrowd submission format"},
        {"id": "intigriti", "name": "Intigriti", "description": "Intigriti report format"},
        {"id": "cve", "name": "CVE Advisory", "description": "CVE-style security advisory"},
        {"id": "executive", "name": "Executive Summary", "description": "Non-technical executive summary"},
        {"id": "technical", "name": "Technical Writeup", "description": "Detailed technical analysis"},
        {"id": "markdown", "name": "Markdown", "description": "Generic markdown report"},
    ]}
