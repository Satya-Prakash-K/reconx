"""Audit logging middleware — records all API activity."""

from __future__ import annotations

import time
import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

import structlog

logger = structlog.get_logger("audit")


class AuditMiddleware(BaseHTTPMiddleware):
    """Middleware to log all API requests for audit trail."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())[:8]
        start = time.perf_counter()

        # Extract user info from JWT if present
        user_id = "anonymous"
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                from reconx_shared.security.rbac import decode_token
                payload = decode_token(auth_header[7:])
                user_id = payload.get("sub", "unknown")
            except Exception:
                pass

        logger.info(
            "API request",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            user=user_id,
            ip=request.client.host if request.client else "unknown",
        )

        response = await call_next(request)
        duration = round((time.perf_counter() - start) * 1000, 2)

        logger.info(
            "API response",
            request_id=request_id,
            status=response.status_code,
            duration_ms=duration,
        )

        response.headers["X-Request-ID"] = request_id
        return response
