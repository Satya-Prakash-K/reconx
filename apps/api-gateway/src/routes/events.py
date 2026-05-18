"""Events routes — real-time feed of reconnaissance events."""

from __future__ import annotations

import json
from fastapi import APIRouter, Depends, Query
from reconx_shared.security.rbac import get_current_user
from reconx_shared.db.redis import RedisManager

import structlog

logger = structlog.get_logger(__name__)
router = APIRouter()

@router.get("/recent")
async def get_recent_events(
    limit: int = Query(100, ge=1, le=500),
    current_user: dict = Depends(get_current_user)
):
    """Fetch recent discovery events from the Redis stream."""
    redis_mgr = RedisManager()
    
    try:
        # XREVRANGE to get newest events first
        messages = await redis_mgr.streams_client.xrevrange(
            "reconx:stream:events", max="+", min="-", count=limit
        )
        
        events = []
        for entry_id, fields in messages:
            try:
                data = json.loads(fields.get("data", "{}"))
                events.append({
                    "id": entry_id,
                    "event_type": fields.get("event_type", "unknown"),
                    "data": data,
                    "timestamp": entry_id.split("-")[0] # Redis ID is timestamp-seq
                })
            except json.JSONDecodeError:
                continue
                
        return {"events": events}
    except Exception as e:
        logger.warning("Failed to fetch recent events", error=str(e))
        return {"events": []}
