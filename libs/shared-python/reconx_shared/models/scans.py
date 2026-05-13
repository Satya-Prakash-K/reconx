"""Scan and recon phase models."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class ScanStatus(str, enum.Enum):
    """Status of a scan."""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReconPhase(str, enum.Enum):
    """Phases of reconnaissance."""
    SUBDOMAIN_ENUMERATION = "subdomain_enumeration"
    DNS_ANALYSIS = "dns_analysis"
    HTTP_PROBING = "http_probing"
    PORT_SCANNING = "port_scanning"
    URL_COLLECTION = "url_collection"
    JS_ANALYSIS = "js_analysis"
    VISUAL_RECON = "visual_recon"
    CLOUD_EXPOSURE = "cloud_exposure"
    API_DISCOVERY = "api_discovery"
    AI_ANALYSIS = "ai_analysis"


class ScanConfig(BaseModel):
    """Configuration for a recon scan."""
    phases: list[ReconPhase] = Field(
        default_factory=lambda: list(ReconPhase),
        description="Recon phases to execute"
    )
    tools_override: Optional[dict[str, list[str]]] = Field(
        None,
        description="Override default tools per phase: {phase: [tool1, tool2]}"
    )
    max_concurrent_tools: int = Field(5, ge=1, le=20)
    safe_mode: bool = True
    safe_mode_delay_ms: int = Field(500, ge=0, le=10000)
    rate_limit_rpm: int = Field(100, ge=1, le=10000)
    dns_wordlist: Optional[str] = None
    port_range: str = "1-10000"
    screenshot_enabled: bool = True
    ai_analysis_enabled: bool = True
    notify_on_completion: bool = True
    custom_headers: Optional[dict[str, str]] = None
    proxy: Optional[str] = None


class ScanCreate(BaseModel):
    """Schema for creating a scan."""
    workspace_id: uuid.UUID
    name: Optional[str] = None
    description: Optional[str] = None
    config: ScanConfig = Field(default_factory=ScanConfig)
    scheduled_at: Optional[datetime] = None


class ScanPhaseResult(BaseModel):
    """Result of a single recon phase."""
    phase: ReconPhase
    status: ScanStatus
    tools_used: list[str] = Field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    assets_found: int = 0
    findings_found: int = 0
    errors: list[str] = Field(default_factory=list)
    duration_seconds: Optional[float] = None


class Scan(BaseModel):
    """A recon scan session."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    workspace_id: uuid.UUID
    name: Optional[str] = None
    description: Optional[str] = None
    status: ScanStatus = ScanStatus.PENDING
    config: ScanConfig = Field(default_factory=ScanConfig)
    current_phase: Optional[ReconPhase] = None
    phase_results: list[ScanPhaseResult] = Field(default_factory=list)
    total_assets_found: int = 0
    total_findings_found: int = 0
    progress_percent: float = 0.0
    temporal_workflow_id: Optional[str] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    scheduled_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True
