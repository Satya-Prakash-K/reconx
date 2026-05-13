"""Scope and program models for bug bounty target management."""

from __future__ import annotations

import enum
import re
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class BountyPlatform(str, enum.Enum):
    """Supported bug bounty platforms."""
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"
    CUSTOM = "custom"


class ScopeType(str, enum.Enum):
    """Type of scope entry."""
    DOMAIN = "domain"
    WILDCARD = "wildcard"
    IP = "ip"
    IP_RANGE = "ip_range"
    URL = "url"
    API = "api"


class ScopeCreate(BaseModel):
    """Schema for creating a scope entry."""
    scope_type: ScopeType
    value: str = Field(..., min_length=1, max_length=500)
    is_in_scope: bool = True
    notes: Optional[str] = None

    @field_validator("value")
    @classmethod
    def validate_scope_value(cls, v: str, info) -> str:  # noqa: N805
        """Validate and normalize scope values."""
        v = v.strip().lower()

        # Remove protocol prefixes for domain types
        if v.startswith(("http://", "https://")):
            v = re.sub(r"^https?://", "", v)

        # Remove trailing slashes and paths for domain scopes
        v = v.split("/")[0]

        # Validate wildcard format
        if v.startswith("*."):
            # Wildcard domain validation
            domain_part = v[2:]
            if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", domain_part):
                raise ValueError(f"Invalid wildcard domain: {v}")
        elif "." in v and not v.replace(".", "").replace("-", "").replace(":", "").isalnum():
            # Basic domain/IP validation
            pass  # Allow through for further validation

        return v


class ScopeEntry(BaseModel):
    """A validated scope entry."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    program_id: uuid.UUID
    scope_type: ScopeType
    value: str
    normalized_value: str
    is_in_scope: bool = True
    is_wildcard: bool = False
    parent_domain: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        from_attributes = True


class ProgramCreate(BaseModel):
    """Schema for creating a bug bounty program."""
    name: str = Field(..., min_length=1, max_length=200)
    platform: BountyPlatform
    platform_url: Optional[str] = None
    description: Optional[str] = None
    scopes: list[ScopeCreate] = Field(default_factory=list)


class Program(BaseModel):
    """A bug bounty program with scope definitions."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    name: str
    platform: BountyPlatform
    platform_url: Optional[str] = None
    description: Optional[str] = None
    is_active: bool = True
    scopes: list[ScopeEntry] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        from_attributes = True


class WorkspaceCreate(BaseModel):
    """Schema for creating an isolated workspace."""
    program_id: uuid.UUID
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None


class Workspace(BaseModel):
    """Isolated workspace per target for scan management."""
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    program_id: uuid.UUID
    name: str
    description: Optional[str] = None
    is_active: bool = True
    scan_count: int = 0
    finding_count: int = 0
    asset_count: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        from_attributes = True
