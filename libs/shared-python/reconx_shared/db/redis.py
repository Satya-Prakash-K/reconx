"""Redis client with connection pooling, caching, and streams support."""

from __future__ import annotations

import json
import os
from typing import Any, Optional

import redis.asyncio as redis

import structlog

logger = structlog.get_logger(__name__)

_clients: dict[int, redis.Redis] = {}


def get_redis_client(db: int = 0) -> redis.Redis:
    """Get or create a Redis async client for a specific database.

    Args:
        db: Redis database number (0=cache, 1=celery, 2=streams).

    Returns:
        Redis async client instance.
    """
    if db not in _clients:
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        base_url = url.rsplit("/", 1)[0] if "/" in url.split("://", 1)[-1] else url
        _clients[db] = redis.from_url(
            f"{base_url}/{db}",
            encoding="utf-8",
            decode_responses=True,
            max_connections=20,
        )
        logger.info("Redis client created", db=db)

    return _clients[db]


class RedisManager:
    """High-level Redis operations for caching and streams."""

    def __init__(self, client: redis.Redis | None = None):
        self.client = client or get_redis_client(0)
        self.streams_client = get_redis_client(2)

    # ── Caching ────────────────────────────────────────────────────

    async def cache_get(self, key: str) -> Optional[Any]:
        """Get a cached value (auto-deserializes JSON)."""
        value = await self.client.get(f"reconx:cache:{key}")
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return None

    async def cache_set(
        self, key: str, value: Any, ttl_seconds: int = 3600
    ) -> None:
        """Set a cached value with TTL (auto-serializes to JSON)."""
        serialized = json.dumps(value) if not isinstance(value, str) else value
        await self.client.setex(f"reconx:cache:{key}", ttl_seconds, serialized)

    async def cache_delete(self, key: str) -> None:
        """Delete a cached key."""
        await self.client.delete(f"reconx:cache:{key}")

    async def cache_invalidate_pattern(self, pattern: str) -> int:
        """Delete all keys matching a pattern."""
        count = 0
        async for key in self.client.scan_iter(f"reconx:cache:{pattern}"):
            await self.client.delete(key)
            count += 1
        return count

    # ── Rate Limiting ──────────────────────────────────────────────

    async def rate_limit_check(
        self, identifier: str, max_requests: int, window_seconds: int = 60
    ) -> tuple[bool, int]:
        """Check and increment rate limit counter.

        Returns:
            Tuple of (is_allowed, remaining_requests).
        """
        key = f"reconx:ratelimit:{identifier}"
        pipe = self.client.pipeline()
        pipe.incr(key)
        pipe.ttl(key)
        results = await pipe.execute()

        current = results[0]
        ttl = results[1]

        if ttl == -1:
            await self.client.expire(key, window_seconds)

        remaining = max(0, max_requests - current)
        allowed = current <= max_requests

        return allowed, remaining

    # ── Redis Streams ──────────────────────────────────────────────

    async def stream_publish(
        self, stream: str, event_type: str, data: dict[str, Any]
    ) -> str:
        """Publish an event to a Redis Stream.

        Returns:
            The stream entry ID.
        """
        message = {
            "event_type": event_type,
            "data": json.dumps(data),
        }
        entry_id = await self.streams_client.xadd(
            f"reconx:stream:{stream}", message, maxlen=10000
        )
        return entry_id

    async def stream_read(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int = 10,
        block_ms: int = 5000,
    ) -> list[dict[str, Any]]:
        """Read from a Redis Stream consumer group."""
        try:
            await self.streams_client.xgroup_create(
                f"reconx:stream:{stream}", group, id="0", mkstream=True
            )
        except redis.ResponseError:
            pass  # Group already exists

        messages = await self.streams_client.xreadgroup(
            group, consumer,
            {f"reconx:stream:{stream}": ">"},
            count=count, block=block_ms,
        )

        results = []
        if messages:
            for stream_name, entries in messages:
                for entry_id, fields in entries:
                    data = json.loads(fields.get("data", "{}"))
                    results.append({
                        "id": entry_id,
                        "event_type": fields.get("event_type", "unknown"),
                        "data": data,
                    })

        return results

    async def stream_ack(self, stream: str, group: str, *ids: str) -> None:
        """Acknowledge processed stream messages."""
        await self.streams_client.xack(f"reconx:stream:{stream}", group, *ids)

    # ── Scan Progress ──────────────────────────────────────────────

    async def set_scan_progress(
        self, scan_id: str, phase: str, progress: float, details: dict[str, Any]
    ) -> None:
        """Update scan progress in real-time."""
        key = f"reconx:scan_progress:{scan_id}"
        data = {
            "phase": phase,
            "progress": str(progress),
            "details": json.dumps(details),
        }
        await self.client.hset(key, mapping=data)
        await self.client.expire(key, 86400)  # 24h TTL

    async def get_scan_progress(self, scan_id: str) -> Optional[dict[str, Any]]:
        """Get current scan progress."""
        key = f"reconx:scan_progress:{scan_id}"
        data = await self.client.hgetall(key)
        if data:
            return {
                "phase": data.get("phase"),
                "progress": float(data.get("progress", 0)),
                "details": json.loads(data.get("details", "{}")),
            }
        return None

    async def close(self) -> None:
        """Close all Redis connections."""
        global _clients
        for client in _clients.values():
            await client.close()
        _clients.clear()
