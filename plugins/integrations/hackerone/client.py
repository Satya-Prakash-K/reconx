"""HackerOne API client for scope import."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)


class HackerOneClient:
    """Client for the HackerOne API v1."""

    BASE_URL = "https://api.hackerone.com/v1"

    def __init__(self, username: str, api_token: str):
        self.client = httpx.AsyncClient(
            auth=(username, api_token),
            headers={"Accept": "application/json"},
            timeout=30.0,
        )

    async def get_programs(self, page: int = 1) -> list[dict[str, Any]]:
        """List bug bounty programs."""
        resp = await self.client.get(
            f"{self.BASE_URL}/hackers/programs",
            params={"page[number]": page, "page[size]": 100},
        )
        resp.raise_for_status()
        return resp.json().get("data", [])

    async def get_program_scopes(self, handle: str) -> list[dict[str, Any]]:
        """Get scope definitions for a specific program."""
        resp = await self.client.get(f"{self.BASE_URL}/hackers/programs/{handle}")
        resp.raise_for_status()
        data = resp.json()

        scopes = []
        structured = data.get("relationships", {}).get("structured_scopes", {}).get("data", [])
        for entry in structured:
            attrs = entry.get("attributes", {})
            scopes.append({
                "value": attrs.get("asset_identifier", ""),
                "asset_type": attrs.get("asset_type", "URL"),
                "eligible_for_bounty": attrs.get("eligible_for_bounty", False),
                "eligible_for_submission": attrs.get("eligible_for_submission", True),
                "instruction": attrs.get("instruction", ""),
            })

        logger.info("Fetched HackerOne scopes", handle=handle, count=len(scopes))
        return scopes

    async def close(self) -> None:
        await self.client.aclose()
