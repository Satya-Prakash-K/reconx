"""JWT authentication and RBAC authorization."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from reconx_shared.models.auth import User, UserRole

import structlog

logger = structlog.get_logger(__name__)

security = HTTPBearer()

JWT_SECRET = os.getenv("JWT_SECRET_KEY", "change-me-jwt-secret-key")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_EXPIRE = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_EXPIRE = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))


def create_access_token(user_id: str, role: str, extra: dict[str, Any] | None = None) -> str:
    """Create a JWT access token."""
    payload = {
        "sub": user_id,
        "role": role,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_EXPIRE),
        "iat": datetime.now(timezone.utc),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    """Create a JWT refresh token."""
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_EXPIRE),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT token."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict[str, Any]:
    """FastAPI dependency to get the current authenticated user."""
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token type")
    return payload


def require_role(*roles: UserRole) -> Callable:
    """Decorator to enforce RBAC on API endpoints."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            user = kwargs.get("current_user")
            if not user:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")

            user_role = UserRole(user.get("role", "viewer"))
            if user_role not in roles:
                logger.warning("RBAC denied", user=user.get("sub"), role=user_role, required=roles)
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    f"Role '{user_role.value}' not authorized. Required: {[r.value for r in roles]}"
                )
            return await func(*args, **kwargs)
        return wrapper
    return decorator
