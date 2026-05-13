"""Endpoint Classifier Agent — AI-powered endpoint analysis and categorization."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger(__name__)


class EndpointClassifierAgent:
    """Classifies endpoints by function, risk level, and testing priority."""

    ENDPOINT_CATEGORIES = {
        "authentication": ["/login", "/signin", "/auth", "/oauth", "/token", "/register", "/signup", "/sso"],
        "user_management": ["/user", "/profile", "/account", "/settings", "/preferences"],
        "admin": ["/admin", "/dashboard", "/manage", "/control", "/panel", "/backoffice"],
        "api": ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc"],
        "file_handling": ["/upload", "/download", "/export", "/import", "/file", "/attachment", "/media"],
        "search": ["/search", "/find", "/query", "/lookup", "/autocomplete"],
        "payment": ["/payment", "/checkout", "/billing", "/invoice", "/cart", "/order"],
        "data_access": ["/data", "/report", "/analytics", "/export", "/csv", "/pdf"],
        "webhook": ["/webhook", "/callback", "/hook", "/notify", "/event"],
        "debug": ["/debug", "/test", "/status", "/health", "/info", "/phpinfo", "/env"],
    }

    async def classify_endpoints(
        self, workspace_id: str, endpoints: list[dict]
    ) -> dict[str, Any]:
        """Classify all endpoints and return enriched data."""
        classified: dict[str, list] = {cat: [] for cat in self.ENDPOINT_CATEGORIES}
        classified["other"] = []

        for ep in endpoints:
            url = ep.get("url", "")
            path = urlparse(url).path.lower()
            categorized = False

            for category, patterns in self.ENDPOINT_CATEGORIES.items():
                if any(pattern in path for pattern in patterns):
                    ep["category"] = category
                    ep["testing_priority"] = self._get_priority(category)
                    classified[category].append(ep)
                    categorized = True
                    break

            if not categorized:
                ep["category"] = "other"
                ep["testing_priority"] = "medium"
                classified["other"].append(ep)

        # Flatten for return
        all_endpoints = []
        for cat_endpoints in classified.values():
            all_endpoints.extend(cat_endpoints)

        summary = {cat: len(eps) for cat, eps in classified.items() if eps}

        logger.info("Endpoints classified", total=len(all_endpoints), categories=summary)

        return {
            "endpoints": all_endpoints,
            "categories": classified,
            "summary": summary,
            "technologies": list({t for ep in endpoints for t in ep.get("technologies", [])}),
        }

    def _get_priority(self, category: str) -> str:
        priority_map = {
            "authentication": "critical",
            "admin": "critical",
            "payment": "critical",
            "file_handling": "high",
            "api": "high",
            "user_management": "high",
            "data_access": "high",
            "debug": "critical",
            "search": "medium",
            "webhook": "medium",
        }
        return priority_map.get(category, "medium")
