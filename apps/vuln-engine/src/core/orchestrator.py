"""Vulnerability Workflow Orchestrator — coordinates multi-phase vuln testing.

Event-driven architecture using Kafka for distributed scan coordination.
Supports adaptive workflows that adjust based on AI analysis.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

import structlog

logger = structlog.get_logger(__name__)


class VulnPhase(str, Enum):
    """Vulnerability testing phases — executed in adaptive order."""
    ANALYSIS = "analysis"               # Analyze recon data
    CLASSIFICATION = "classification"   # AI endpoint classification
    HYPOTHESIS = "hypothesis"           # AI vulnerability hypothesis
    PASSIVE_DETECTION = "passive"       # Passive checks (headers, config)
    FUZZING = "fuzzing"                 # Intelligent fuzzing
    ACTIVE_TESTING = "active"           # Active vuln testing
    VALIDATION = "validation"           # Validate findings
    EXPLOITATION = "exploitation"       # Proof-of-concept generation
    REPORTING = "reporting"             # AI report generation


class VulnCategory(str, Enum):
    """Vulnerability categories for the 15 modules."""
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    IDOR = "idor"
    AUTH_FLAW = "auth_flaw"
    AUTHZ_BYPASS = "authz_bypass"
    JWT_WEAKNESS = "jwt_weakness"
    GRAPHQL = "graphql"
    FILE_UPLOAD = "file_upload"
    OPEN_REDIRECT = "open_redirect"
    CORS_MISCONFIG = "cors_misconfig"
    API_SECURITY = "api_security"
    DATA_EXPOSURE = "data_exposure"
    MISCONFIGURATION = "misconfiguration"
    CLOUD_EXPOSURE = "cloud_exposure"


class VulnScanConfig(BaseModel):
    """Configuration for a vulnerability scan."""
    workspace_id: str
    target_urls: list[str] = Field(default_factory=list)
    categories: list[VulnCategory] = Field(
        default_factory=lambda: list(VulnCategory)
    )
    phases: list[VulnPhase] = Field(
        default_factory=lambda: [
            VulnPhase.ANALYSIS, VulnPhase.CLASSIFICATION,
            VulnPhase.HYPOTHESIS, VulnPhase.PASSIVE_DETECTION,
            VulnPhase.FUZZING, VulnPhase.ACTIVE_TESTING,
            VulnPhase.VALIDATION, VulnPhase.REPORTING,
        ]
    )
    max_concurrent: int = Field(10, ge=1, le=50)
    safe_mode: bool = True
    throttle_rps: float = Field(10.0, ge=0.1, le=100.0)
    auth_config: Optional[AuthConfig] = None
    waf_evasion: bool = False
    browser_testing: bool = True
    ai_hypothesis: bool = True
    depth: int = Field(3, ge=1, le=10)


class AuthConfig(BaseModel):
    """Authentication configuration for authenticated scanning."""
    auth_type: str = "bearer"  # bearer, cookie, basic, oauth2, custom
    credentials: dict[str, str] = Field(default_factory=dict)
    login_url: Optional[str] = None
    login_payload: Optional[dict[str, str]] = None
    token_field: Optional[str] = None
    session_cookies: Optional[dict[str, str]] = None
    multi_account: list[dict[str, str]] = Field(default_factory=list)


class VulnScanStatus(BaseModel):
    """Real-time status of a vulnerability scan."""
    scan_id: str
    status: str = "pending"
    current_phase: Optional[VulnPhase] = None
    progress: float = 0.0
    endpoints_tested: int = 0
    endpoints_total: int = 0
    vulns_found: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    phase_results: dict[str, Any] = Field(default_factory=dict)
    ai_reasoning: list[str] = Field(default_factory=list)
    started_at: Optional[datetime] = None
    elapsed_seconds: float = 0.0


class VulnWorkflowOrchestrator:
    """Orchestrates the full vulnerability testing workflow.

    Implements an adaptive pipeline that:
    1. Analyzes recon data to identify attack surfaces
    2. Uses AI to generate vulnerability hypotheses
    3. Prioritizes testing based on exploitability
    4. Runs intelligent fuzzing with adaptive payloads
    5. Validates findings to reduce false positives
    6. Generates proof-of-concept and reports
    """

    def __init__(self):
        self._active_scans: dict[str, VulnScanStatus] = {}

    async def start_scan(self, config: VulnScanConfig) -> VulnScanStatus:
        """Start a vulnerability scan workflow."""
        scan_id = str(uuid.uuid4())
        status = VulnScanStatus(
            scan_id=scan_id,
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        self._active_scans[scan_id] = status

        logger.info(
            "Vulnerability scan started",
            scan_id=scan_id,
            targets=len(config.target_urls),
            categories=len(config.categories),
        )

        # Publish scan event to Kafka
        try:
            from reconx_shared.kafka import publish_event
            await publish_event("vuln_scans", "scan_started", {
                "scan_id": scan_id,
                "workspace_id": config.workspace_id,
                "config": config.model_dump(),
            })
        except Exception as e:
            logger.warning("Kafka publish failed", error=str(e))

        # Execute phases
        asyncio.create_task(self._execute_pipeline(scan_id, config, status))

        return status

    async def _execute_pipeline(
        self, scan_id: str, config: VulnScanConfig, status: VulnScanStatus
    ) -> None:
        """Execute the vulnerability testing pipeline."""
        try:
            for i, phase in enumerate(config.phases):
                status.current_phase = phase
                status.progress = (i / len(config.phases)) * 100

                logger.info("Executing phase", scan_id=scan_id, phase=phase.value)

                if phase == VulnPhase.ANALYSIS:
                    await self._phase_analysis(scan_id, config, status)
                elif phase == VulnPhase.CLASSIFICATION:
                    await self._phase_classification(scan_id, config, status)
                elif phase == VulnPhase.HYPOTHESIS:
                    await self._phase_hypothesis(scan_id, config, status)
                elif phase == VulnPhase.PASSIVE_DETECTION:
                    await self._phase_passive(scan_id, config, status)
                elif phase == VulnPhase.FUZZING:
                    await self._phase_fuzzing(scan_id, config, status)
                elif phase == VulnPhase.ACTIVE_TESTING:
                    await self._phase_active(scan_id, config, status)
                elif phase == VulnPhase.VALIDATION:
                    await self._phase_validation(scan_id, config, status)
                elif phase == VulnPhase.REPORTING:
                    await self._phase_reporting(scan_id, config, status)

            status.status = "completed"
            status.progress = 100.0
            logger.info("Vulnerability scan completed", scan_id=scan_id, vulns=status.vulns_found)

        except Exception as e:
            status.status = "failed"
            logger.error("Vulnerability scan failed", scan_id=scan_id, error=str(e))

    async def _phase_analysis(self, scan_id: str, config: VulnScanConfig, status: VulnScanStatus):
        """Phase 1: Analyze recon data and identify attack surfaces."""
        from src.core.attack_surface_analyzer import AttackSurfaceAnalyzer
        analyzer = AttackSurfaceAnalyzer()
        result = await analyzer.analyze(config.workspace_id, config.target_urls)
        status.endpoints_total = result.get("total_endpoints", 0)
        status.phase_results["analysis"] = result
        status.ai_reasoning.append(f"Identified {status.endpoints_total} endpoints for testing")

    async def _phase_classification(self, scan_id: str, config: VulnScanConfig, status: VulnScanStatus):
        """Phase 2: AI-powered endpoint classification."""
        from src.agents.classifier_agent import EndpointClassifierAgent
        agent = EndpointClassifierAgent()
        classifications = await agent.classify_endpoints(
            config.workspace_id,
            status.phase_results.get("analysis", {}).get("endpoints", [])
        )
        status.phase_results["classification"] = classifications
        status.ai_reasoning.append(f"Classified endpoints into {len(classifications)} categories")

    async def _phase_hypothesis(self, scan_id: str, config: VulnScanConfig, status: VulnScanStatus):
        """Phase 3: AI vulnerability hypothesis generation."""
        from src.agents.hypothesis_agent import VulnHypothesisAgent
        agent = VulnHypothesisAgent()
        hypotheses = await agent.generate_hypotheses(
            status.phase_results.get("classification", {}),
            config.categories,
        )
        status.phase_results["hypotheses"] = hypotheses
        status.ai_reasoning.append(f"Generated {len(hypotheses)} vulnerability hypotheses")

    async def _phase_passive(self, scan_id: str, config: VulnScanConfig, status: VulnScanStatus):
        """Phase 4: Passive vulnerability detection."""
        from src.core.passive_detector import PassiveDetector
        detector = PassiveDetector()
        findings = await detector.detect(config.target_urls, config.categories)
        status.phase_results["passive"] = findings
        status.vulns_found += len(findings)

    async def _phase_fuzzing(self, scan_id: str, config: VulnScanConfig, status: VulnScanStatus):
        """Phase 5: Intelligent fuzzing."""
        from src.fuzzing.engine import FuzzingEngine
        engine = FuzzingEngine()
        findings = await engine.fuzz(
            endpoints=status.phase_results.get("analysis", {}).get("endpoints", []),
            hypotheses=status.phase_results.get("hypotheses", []),
            config=config,
        )
        status.phase_results["fuzzing"] = findings
        status.vulns_found += len(findings)

    async def _phase_active(self, scan_id: str, config: VulnScanConfig, status: VulnScanStatus):
        """Phase 6: Active vulnerability testing with specialized modules."""
        from src.core.module_runner import VulnModuleRunner
        runner = VulnModuleRunner()
        findings = await runner.run_modules(
            targets=config.target_urls,
            categories=config.categories,
            auth=config.auth_config,
            hypotheses=status.phase_results.get("hypotheses", []),
        )
        status.phase_results["active"] = findings
        status.vulns_found += len(findings)

    async def _phase_validation(self, scan_id: str, config: VulnScanConfig, status: VulnScanStatus):
        """Phase 7: Validate and deduplicate findings."""
        from src.agents.validation_agent import ValidationAgent
        agent = ValidationAgent()
        all_findings = []
        for phase_key in ("passive", "fuzzing", "active"):
            all_findings.extend(status.phase_results.get(phase_key, []))

        validated = await agent.validate_findings(all_findings)
        status.phase_results["validated"] = validated

        # Update severity counts
        for f in validated:
            sev = f.get("severity", "info")
            if sev == "critical": status.critical += 1
            elif sev == "high": status.high += 1
            elif sev == "medium": status.medium += 1
            elif sev == "low": status.low += 1
            else: status.info += 1

        status.vulns_found = len(validated)
        status.ai_reasoning.append(
            f"Validated {len(validated)} findings (reduced from {len(all_findings)} raw)"
        )

    async def _phase_reporting(self, scan_id: str, config: VulnScanConfig, status: VulnScanStatus):
        """Phase 8: Generate AI reports and reproduction steps."""
        from src.agents.reporting_agent import ReportingAgent
        agent = ReportingAgent()
        report = await agent.generate_report(
            scan_id=scan_id,
            workspace_id=config.workspace_id,
            findings=status.phase_results.get("validated", []),
        )
        status.phase_results["report"] = report

    def get_status(self, scan_id: str) -> Optional[VulnScanStatus]:
        return self._active_scans.get(scan_id)

    def list_active(self) -> list[VulnScanStatus]:
        return list(self._active_scans.values())


# Singleton
_orchestrator: VulnWorkflowOrchestrator | None = None


def get_orchestrator() -> VulnWorkflowOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = VulnWorkflowOrchestrator()
    return _orchestrator
