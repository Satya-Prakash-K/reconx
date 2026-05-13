"""Bug bounty program management routes."""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text

from reconx_shared.models.scope import (
    BountyPlatform, Program, ProgramCreate, ScopeCreate, ScopeEntry, ScopeType,
)
from reconx_shared.security.rbac import get_current_user, require_role
from reconx_shared.models.auth import UserRole
from reconx_shared.db.postgres import get_db_session

import structlog

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post("/", response_model=Program, status_code=status.HTTP_201_CREATED)
async def create_program(
    data: ProgramCreate,
    current_user: dict = Depends(get_current_user),
):
    """Create a new bug bounty program with scope definitions."""
    program_id = uuid.uuid4()

    async with get_db_session() as session:
        await session.execute(
            text("""
                INSERT INTO programs (id, name, platform, platform_url, description, created_by)
                VALUES (:id, :name, :platform, :url, :desc, :user_id)
            """),
            {
                "id": str(program_id),
                "name": data.name,
                "platform": data.platform.value,
                "url": data.platform_url,
                "desc": data.description,
                "user_id": current_user["sub"],
            },
        )

        # Add scope entries
        scopes = []
        for scope in data.scopes:
            scope_id = uuid.uuid4()
            normalized = scope.value.strip().lower()
            is_wildcard = normalized.startswith("*.")
            parent_domain = normalized[2:] if is_wildcard else None

            await session.execute(
                text("""
                    INSERT INTO scopes (id, program_id, scope_type, value, normalized_value,
                                       is_in_scope, is_wildcard, parent_domain, notes)
                    VALUES (:id, :pid, :type, :val, :norm, :in_scope, :wild, :parent, :notes)
                """),
                {
                    "id": str(scope_id), "pid": str(program_id),
                    "type": scope.scope_type.value, "val": scope.value,
                    "norm": normalized, "in_scope": scope.is_in_scope,
                    "wild": is_wildcard, "parent": parent_domain,
                    "notes": scope.notes,
                },
            )
            scopes.append(ScopeEntry(
                id=scope_id, program_id=program_id,
                scope_type=scope.scope_type, value=scope.value,
                normalized_value=normalized, is_in_scope=scope.is_in_scope,
                is_wildcard=is_wildcard, parent_domain=parent_domain,
                notes=scope.notes,
            ))

    logger.info("Program created", program_id=str(program_id), name=data.name)
    return Program(
        id=program_id, name=data.name, platform=data.platform,
        platform_url=data.platform_url, description=data.description,
        scopes=scopes,
    )


@router.get("/", response_model=list[Program])
async def list_programs(
    platform: Optional[BountyPlatform] = None,
    active_only: bool = True,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
):
    """List bug bounty programs with optional filtering."""
    conditions = []
    params: dict = {"limit": limit, "offset": offset}

    if active_only:
        conditions.append("p.is_active = true")
    if platform:
        conditions.append("p.platform = :platform")
        params["platform"] = platform.value

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    async with get_db_session() as session:
        result = await session.execute(
            text(f"""
                SELECT p.id, p.name, p.platform, p.platform_url, p.description,
                       p.is_active, p.created_at, p.updated_at
                FROM programs p {where}
                ORDER BY p.updated_at DESC
                LIMIT :limit OFFSET :offset
            """),
            params,
        )
        rows = result.fetchall()

        programs = []
        for row in rows:
            # Fetch scopes for each program
            scope_result = await session.execute(
                text("SELECT * FROM scopes WHERE program_id = :pid"),
                {"pid": str(row.id)},
            )
            scope_rows = scope_result.fetchall()
            scopes = [
                ScopeEntry(
                    id=s.id, program_id=s.program_id,
                    scope_type=ScopeType(s.scope_type), value=s.value,
                    normalized_value=s.normalized_value, is_in_scope=s.is_in_scope,
                    is_wildcard=s.is_wildcard, parent_domain=s.parent_domain,
                )
                for s in scope_rows
            ]

            programs.append(Program(
                id=row.id, name=row.name, platform=BountyPlatform(row.platform),
                platform_url=row.platform_url, description=row.description,
                is_active=row.is_active, scopes=scopes,
                created_at=row.created_at, updated_at=row.updated_at,
            ))

    return programs


@router.get("/{program_id}", response_model=Program)
async def get_program(program_id: uuid.UUID, current_user: dict = Depends(get_current_user)):
    """Get a specific program with its scopes."""
    async with get_db_session() as session:
        result = await session.execute(
            text("SELECT * FROM programs WHERE id = :id"),
            {"id": str(program_id)},
        )
        row = result.fetchone()
        if not row:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Program not found")

        scope_result = await session.execute(
            text("SELECT * FROM scopes WHERE program_id = :pid"),
            {"pid": str(program_id)},
        )
        scopes = [
            ScopeEntry(
                id=s.id, program_id=s.program_id,
                scope_type=ScopeType(s.scope_type), value=s.value,
                normalized_value=s.normalized_value, is_in_scope=s.is_in_scope,
                is_wildcard=s.is_wildcard, parent_domain=s.parent_domain,
            )
            for s in scope_result.fetchall()
        ]

    return Program(
        id=row.id, name=row.name, platform=BountyPlatform(row.platform),
        platform_url=row.platform_url, description=row.description,
        is_active=row.is_active, scopes=scopes,
        created_at=row.created_at, updated_at=row.updated_at,
    )


@router.delete("/{program_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_program(program_id: uuid.UUID, current_user: dict = Depends(get_current_user)):
    """Soft-delete a program."""
    async with get_db_session() as session:
        await session.execute(
            text("UPDATE programs SET is_active = false WHERE id = :id"),
            {"id": str(program_id)},
        )
    logger.info("Program deactivated", program_id=str(program_id))
