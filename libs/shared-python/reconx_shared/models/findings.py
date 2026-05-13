"""Finding and asset models for recon results."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class AssetType(str, enum.Enum):
    """Types of discovered assets."""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    URL = "url"
    API_ENDPOINT = "api_endpoint"
    JS_FILE = "js_file"
    S3_BUCKET = "s3_bucket"
    AZURE_BLOB = "azure_blob"
    GCP_BUCKET = "gcp_bucket"
    FIREBASE = "firebase"
    GRAPHQL = "graphql"
    SWAGGER = "swagger"


class FindingSeverity(str, enum.Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    """Status of a finding."""
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    REPORTED = "reported"
    RESOLVED = "resolved"


class AssetCreate(BaseModel):
    """Schema for creating a discovered asset."""
    workspace_id: uuid.UUID
    asset_type: AssetType
    value: str = Field(..., min_length=1, max_length=2000)
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[str] = None
    technology: Optional[list[str]] = None
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    content_length: Optional[int] = None
    tls_info: Optional[dict[str, Any]] = None
    waf_detected: Optional[str] = None
    cdn_detected: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class Asset(BaseModel):
    """A discovered asset in the attack surface."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    workspace_id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    asset_type: AssetType
    value: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    technology: list[str] = Field(default_factory=list)
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    content_length: Optional[int] = None
    tls_info: Optional[dict[str, Any]] = None
    waf_detected: Optional[str] = None
    cdn_detected: Optional[str] = None
    risk_score: float = 0.0
    is_alive: bool = True
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class FindingCreate(BaseModel):
    """Schema for creating a finding."""
    workspace_id: uuid.UUID
    asset_id: Optional[uuid.UUID] = None
    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field(..., min_length=1)
    severity: FindingSeverity = FindingSeverity.INFO
    finding_type: str = Field(..., min_length=1, max_length=100)
    evidence: Optional[dict[str, Any]] = None
    reproduction_steps: Optional[str] = None
    affected_url: Optional[str] = None
    source_tool: Optional[str] = None
    tags: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """A security finding from recon."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    workspace_id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    asset_id: Optional[uuid.UUID] = None
    title: str
    description: str
    severity: FindingSeverity
    status: FindingStatus = FindingStatus.NEW
    finding_type: str
    risk_score: float = 0.0
    confidence: float = 0.0
    evidence: dict[str, Any] = Field(default_factory=dict)
    reproduction_steps: Optional[str] = None
    affected_url: Optional[str] = None
    source_tool: Optional[str] = None
    ai_summary: Optional[str] = None
    ai_attack_path: Optional[str] = None
    is_duplicate: bool = False
    duplicate_of: Optional[uuid.UUID] = None
    tags: list[str] = Field(default_factory=list)
    embedding_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        from_attributes = True
