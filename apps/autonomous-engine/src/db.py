"""PostgreSQL connection pool for the autonomous engine."""
from __future__ import annotations
import asyncpg
import os
import structlog

logger = structlog.get_logger(__name__)

_pool: asyncpg.Pool | None = None

DB_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://reconx:reconx_secure_password@postgres:5432/reconx"
)


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        try:
            _pool = await asyncpg.create_pool(DB_URL, min_size=1, max_size=5, command_timeout=10)
            logger.info("PostgreSQL pool created", url=DB_URL.split("@")[-1])
        except Exception as e:
            logger.warning("PostgreSQL unavailable — findings will be in-memory only", error=str(e))
            _pool = None
    return _pool


async def execute(sql: str, *args):
    pool = await get_pool()
    if not pool:
        return None
    try:
        async with pool.acquire() as conn:
            return await conn.execute(sql, *args)
    except Exception as e:
        logger.error("DB execute failed", error=str(e), sql=sql[:80])
        return None


async def fetch(sql: str, *args) -> list[dict]:
    pool = await get_pool()
    if not pool:
        return []
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(sql, *args)
            return [dict(r) for r in rows]
    except Exception as e:
        logger.error("DB fetch failed", error=str(e), sql=sql[:80])
        return []


async def fetchrow(sql: str, *args) -> dict | None:
    pool = await get_pool()
    if not pool:
        return None
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(sql, *args)
            return dict(row) if row else None
    except Exception as e:
        logger.error("DB fetchrow failed", error=str(e), sql=sql[:80])
        return None
