"""Triage API routes — automated finding analysis and prioritization."""

from __future__ import annotations
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


class TriageRequest(BaseModel):
    workspace_id: str
    findings: list[dict]


class TriageSingleRequest(BaseModel):
    workspace_id: str
    finding: dict


@router.post("/batch")
async def triage_batch(request: TriageRequest):
    """Triage a batch of findings through the full AI pipeline."""
    from src.triage.pipeline import TriagePipeline
    pipeline = TriagePipeline()
    results = await pipeline.triage(request.findings, request.workspace_id)
    unique = [r for r in results if not r.is_duplicate]
    dupes = [r for r in results if r.is_duplicate]
    return {
        "total": len(results),
        "unique": len(unique),
        "duplicates": len(dupes),
        "findings": [r.model_dump() for r in unique],
        "duplicate_ids": [r.id for r in dupes],
    }


@router.post("/single")
async def triage_single(request: TriageSingleRequest):
    """Triage a single finding."""
    from src.triage.pipeline import TriagePipeline
    pipeline = TriagePipeline()
    results = await pipeline.triage([request.finding], request.workspace_id)
    if results:
        return results[0].model_dump()
    raise HTTPException(status_code=400, detail="Triage failed")


@router.post("/deduplicate")
async def deduplicate(request: TriageRequest):
    """Run deduplication only on findings."""
    from src.triage.pipeline import DeduplicationEngine
    from src.triage.pipeline import TriagePipeline
    pipeline = TriagePipeline()
    triaged = [pipeline._to_triaged(f, request.workspace_id) for f in request.findings]
    result = await pipeline.dedup_engine.deduplicate(triaged)
    return {
        "total": len(result),
        "unique": sum(1 for r in result if not r.is_duplicate),
        "duplicates": sum(1 for r in result if r.is_duplicate),
    }


@router.post("/classify-cwe")
async def classify_cwe(finding: dict):
    """Classify a finding by CWE."""
    from src.triage.pipeline import CWEClassifier, TriagePipeline
    pipeline = TriagePipeline()
    triaged = pipeline._to_triaged(finding, "")
    cwe = pipeline.cwe_classifier.classify(triaged)
    return cwe


@router.post("/estimate-cvss")
async def estimate_cvss(finding: dict):
    """Estimate CVSS score for a finding."""
    from src.triage.pipeline import CVSSEstimator, TriagePipeline
    pipeline = TriagePipeline()
    triaged = pipeline._to_triaged(finding, "")
    cvss = pipeline.cvss_estimator.estimate(triaged)
    return cvss
