"""Advanced analysis API routes."""

from __future__ import annotations
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class AnalysisRequest(BaseModel):
    base_url: str


class OAuthRequest(BaseModel):
    auth_url: str
    client_id: str = ""


@router.post("/oauth")
async def analyze_oauth(request: OAuthRequest):
    """Analyze OAuth implementation."""
    from src.analysis.advanced import OAuthFlowAnalyzer
    analyzer = OAuthFlowAnalyzer()
    findings = await analyzer.analyze(request.auth_url, request.client_id)
    return {"findings": findings}


@router.post("/cicd")
async def scan_cicd(request: AnalysisRequest):
    """Scan for exposed CI/CD artifacts."""
    from src.analysis.advanced import CICDExposureAnalyzer
    analyzer = CICDExposureAnalyzer()
    findings = await analyzer.scan(request.base_url)
    return {"findings": findings}


@router.post("/k8s-exposure")
async def scan_k8s(request: AnalysisRequest):
    """Scan for K8s exposure."""
    from src.analysis.advanced import KubernetesExposureAnalyzer
    analyzer = KubernetesExposureAnalyzer()
    findings = await analyzer.scan(request.base_url)
    return {"findings": findings}


@router.post("/secrets")
async def scan_secrets(request: AnalysisRequest):
    """Scan for secret leakage."""
    from src.analysis.advanced import SecretLeakageIntelligence
    scanner = SecretLeakageIntelligence()
    findings = await scanner.scan_url(request.base_url)
    return {"findings": findings}


@router.post("/api-spec")
async def analyze_api(request: AnalysisRequest):
    """Analyze REST API specification."""
    from src.analysis.advanced import RESTAPIAnalyzer
    analyzer = RESTAPIAnalyzer()
    findings = await analyzer.analyze_spec(request.base_url)
    return {"findings": findings}
