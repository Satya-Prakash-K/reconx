"""Health check endpoints."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health", summary="Health check")
async def health_check():
    return {"status": "healthy", "service": "reconx-api-gateway", "version": "0.1.0"}


@router.get("/ready", summary="Readiness check")
async def readiness_check():
    checks = {"postgres": True, "redis": True}
    try:
        from reconx_shared.db.redis import get_redis_client
        client = get_redis_client()
        await client.ping()
    except Exception:
        checks["redis"] = False

    all_ready = all(checks.values())
    return {"ready": all_ready, "checks": checks}
