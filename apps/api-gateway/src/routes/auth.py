"""Authentication routes — register, login, refresh."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status, Depends
from passlib.context import CryptContext

from reconx_shared.models.auth import UserCreate, User, UserRole, TokenPair
from reconx_shared.security.rbac import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
)
from reconx_shared.db.postgres import get_db_session

from sqlalchemy import text

import structlog

logger = structlog.get_logger(__name__)
router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@router.post("/register", response_model=User, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate):
    """Register a new user."""
    async with get_db_session() as session:
        # Check existing user
        result = await session.execute(
            text("SELECT id FROM users WHERE username = :u OR email = :e"),
            {"u": user_data.username, "e": user_data.email},
        )
        if result.fetchone():
            raise HTTPException(status.HTTP_409_CONFLICT, "User already exists")

        user_id = uuid.uuid4()
        password_hash = pwd_context.hash(user_data.password)

        await session.execute(
            text("""
                INSERT INTO users (id, username, email, password_hash, role)
                VALUES (:id, :username, :email, :password_hash, :role)
            """),
            {
                "id": str(user_id),
                "username": user_data.username,
                "email": user_data.email,
                "password_hash": password_hash,
                "role": user_data.role.value,
            },
        )

    logger.info("User registered", username=user_data.username)
    return User(
        id=user_id,
        username=user_data.username,
        email=user_data.email,
        role=user_data.role,
    )


@router.post("/login", response_model=TokenPair)
async def login(username: str, password: str):
    """Authenticate and get JWT tokens."""
    async with get_db_session() as session:
        result = await session.execute(
            text("SELECT id, username, email, password_hash, role FROM users WHERE username = :u AND is_active = true"),
            {"u": username},
        )
        row = result.fetchone()
        if not row or not pwd_context.verify(password, row.password_hash):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

        # Update last login
        await session.execute(
            text("UPDATE users SET last_login = :now WHERE id = :id"),
            {"now": datetime.now(timezone.utc), "id": str(row.id)},
        )

    access = create_access_token(str(row.id), row.role)
    refresh = create_refresh_token(str(row.id))

    logger.info("User logged in", username=username)
    return TokenPair(access_token=access, refresh_token=refresh, expires_in=1800)


@router.post("/refresh", response_model=TokenPair)
async def refresh_token(refresh_token: str):
    """Refresh an access token."""
    payload = decode_token(refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    user_id = payload["sub"]
    async with get_db_session() as session:
        result = await session.execute(
            text("SELECT role FROM users WHERE id = :id AND is_active = true"),
            {"id": user_id},
        )
        row = result.fetchone()
        if not row:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")

    access = create_access_token(user_id, row.role)
    new_refresh = create_refresh_token(user_id)
    return TokenPair(access_token=access, refresh_token=new_refresh, expires_in=1800)


@router.get("/me", response_model=User)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current authenticated user profile."""
    async with get_db_session() as session:
        result = await session.execute(
            text("SELECT id, username, email, role, is_active, last_login, created_at FROM users WHERE id = :id"),
            {"id": current_user["sub"]},
        )
        row = result.fetchone()
        if not row:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    return User(
        id=row.id,
        username=row.username,
        email=row.email,
        role=UserRole(row.role),
        is_active=row.is_active,
        last_login=row.last_login,
        created_at=row.created_at,
    )
