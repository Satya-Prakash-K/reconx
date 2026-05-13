"""Elasticsearch/OpenSearch async client wrapper."""

from __future__ import annotations

import os
from typing import Any, Optional

from elasticsearch import AsyncElasticsearch

import structlog

logger = structlog.get_logger(__name__)

_client: AsyncElasticsearch | None = None


def get_es_client() -> AsyncElasticsearch:
    """Get or create the Elasticsearch async client."""
    global _client

    if _client is None:
        url = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
        user = os.getenv("ELASTICSEARCH_USER", "elastic")
        password = os.getenv("ELASTICSEARCH_PASSWORD", "elastic_password")

        _client = AsyncElasticsearch(
            hosts=[url],
            basic_auth=(user, password) if user else None,
            verify_certs=False,
            request_timeout=30,
            max_retries=3,
            retry_on_timeout=True,
        )
        logger.info("Elasticsearch client created", url=url)

    return _client


class ElasticsearchManager:
    """High-level Elasticsearch operations for ReconX."""

    def __init__(self, client: AsyncElasticsearch | None = None):
        self.client = client or get_es_client()
        self.index_prefix = os.getenv("ELASTICSEARCH_INDEX_PREFIX", "reconx")

    def _index_name(self, name: str) -> str:
        return f"{self.index_prefix}-{name}"

    async def ensure_indices(self) -> None:
        """Create indices with mappings if they don't exist."""
        indices = {
            "findings": FINDINGS_MAPPING,
            "assets": ASSETS_MAPPING,
            "urls": URLS_MAPPING,
        }

        for name, mapping in indices.items():
            index = self._index_name(name)
            exists = await self.client.indices.exists(index=index)
            if not exists:
                await self.client.indices.create(index=index, body=mapping)
                logger.info("Created ES index", index=index)

    async def index_finding(self, finding_id: str, document: dict[str, Any]) -> None:
        """Index a finding document."""
        await self.client.index(
            index=self._index_name("findings"),
            id=finding_id,
            document=document,
        )

    async def index_asset(self, asset_id: str, document: dict[str, Any]) -> None:
        """Index an asset document."""
        await self.client.index(
            index=self._index_name("assets"),
            id=asset_id,
            document=document,
        )

    async def search_findings(
        self,
        query: str,
        workspace_id: Optional[str] = None,
        severity: Optional[str] = None,
        size: int = 50,
    ) -> dict[str, Any]:
        """Full-text search over findings."""
        must_clauses: list[dict[str, Any]] = [
            {
                "multi_match": {
                    "query": query,
                    "fields": ["title^3", "description^2", "evidence", "tags"],
                    "type": "best_fields",
                    "fuzziness": "AUTO",
                }
            }
        ]

        if workspace_id:
            must_clauses.append({"term": {"workspace_id": workspace_id}})
        if severity:
            must_clauses.append({"term": {"severity": severity}})

        body = {
            "query": {"bool": {"must": must_clauses}},
            "size": size,
            "sort": [{"_score": "desc"}, {"created_at": "desc"}],
            "highlight": {
                "fields": {
                    "title": {},
                    "description": {"fragment_size": 200},
                }
            },
        }

        return await self.client.search(index=self._index_name("findings"), body=body)

    async def close(self) -> None:
        """Close the client."""
        global _client
        if self.client:
            await self.client.close()
            _client = None


# ── Index Mappings ─────────────────────────────────────────────────

FINDINGS_MAPPING = {
    "settings": {
        "number_of_shards": 2,
        "number_of_replicas": 1,
        "analysis": {
            "analyzer": {
                "url_analyzer": {
                    "type": "custom",
                    "tokenizer": "uax_url_email",
                    "filter": ["lowercase"],
                }
            }
        },
    },
    "mappings": {
        "properties": {
            "workspace_id": {"type": "keyword"},
            "scan_id": {"type": "keyword"},
            "title": {"type": "text", "analyzer": "standard"},
            "description": {"type": "text", "analyzer": "standard"},
            "severity": {"type": "keyword"},
            "status": {"type": "keyword"},
            "finding_type": {"type": "keyword"},
            "risk_score": {"type": "float"},
            "confidence": {"type": "float"},
            "evidence": {"type": "text"},
            "affected_url": {"type": "text", "analyzer": "url_analyzer"},
            "source_tool": {"type": "keyword"},
            "tags": {"type": "keyword"},
            "ai_summary": {"type": "text"},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"},
        }
    },
}

ASSETS_MAPPING = {
    "settings": {"number_of_shards": 2, "number_of_replicas": 1},
    "mappings": {
        "properties": {
            "workspace_id": {"type": "keyword"},
            "asset_type": {"type": "keyword"},
            "value": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "hostname": {"type": "keyword"},
            "ip_address": {"type": "ip"},
            "port": {"type": "integer"},
            "protocol": {"type": "keyword"},
            "technology": {"type": "keyword"},
            "http_status": {"type": "integer"},
            "http_title": {"type": "text"},
            "waf_detected": {"type": "keyword"},
            "cdn_detected": {"type": "keyword"},
            "risk_score": {"type": "float"},
            "is_alive": {"type": "boolean"},
            "first_seen": {"type": "date"},
            "last_seen": {"type": "date"},
        }
    },
}

URLS_MAPPING = {
    "settings": {"number_of_shards": 2, "number_of_replicas": 1},
    "mappings": {
        "properties": {
            "workspace_id": {"type": "keyword"},
            "url": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "domain": {"type": "keyword"},
            "path": {"type": "text"},
            "parameters": {"type": "keyword"},
            "source": {"type": "keyword"},
            "status_code": {"type": "integer"},
            "content_type": {"type": "keyword"},
            "discovered_at": {"type": "date"},
        }
    },
}
