"""Rate limiting middleware using SlowAPI."""

from __future__ import annotations

from fastapi import FastAPI, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address


def get_identifier(request: Request) -> str:
    """Get rate limit identifier from JWT user or IP."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        try:
            from reconx_shared.security.rbac import decode_token
            payload = decode_token(auth[7:])
            return f"user:{payload.get('sub', 'unknown')}"
        except Exception:
            pass
    return f"ip:{get_remote_address(request)}"


limiter = Limiter(key_func=get_identifier)


def setup_rate_limiting(app: FastAPI) -> None:
    """Configure rate limiting on the FastAPI app."""
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
