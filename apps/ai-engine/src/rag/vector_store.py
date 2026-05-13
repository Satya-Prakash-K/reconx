"""RAG (Retrieval Augmented Generation) with Qdrant vector store."""

from __future__ import annotations

import os
import uuid
from typing import Any, Optional

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct, Filter, FieldCondition, MatchValue

import structlog

logger = structlog.get_logger(__name__)


class ReconRAG:
    """RAG pipeline for semantic search and context-augmented AI responses."""

    def __init__(self):
        self.client = QdrantClient(
            url=os.getenv("QDRANT_URL", "http://localhost:6333"),
            api_key=os.getenv("QDRANT_API_KEY", None),
        )
        self.collection = os.getenv("QDRANT_COLLECTION", "reconx_findings")
        self.embedding_dim = 384  # For all-MiniLM-L6-v2

    async def init_collection(self) -> None:
        """Create the Qdrant collection if it doesn't exist."""
        collections = self.client.get_collections().collections
        names = [c.name for c in collections]

        if self.collection not in names:
            self.client.create_collection(
                collection_name=self.collection,
                vectors_config=VectorParams(size=self.embedding_dim, distance=Distance.COSINE),
            )
            logger.info("Created Qdrant collection", collection=self.collection)

    async def index_finding(
        self, finding_id: str, text: str, embedding: list[float],
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Index a finding with its embedding for semantic search."""
        point = PointStruct(
            id=str(uuid.uuid5(uuid.NAMESPACE_DNS, finding_id)),
            vector=embedding,
            payload={
                "finding_id": finding_id,
                "text": text,
                **(metadata or {}),
            },
        )
        self.client.upsert(collection_name=self.collection, points=[point])

    async def search(
        self, query_embedding: list[float],
        workspace_id: Optional[str] = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Semantic search over indexed findings."""
        query_filter = None
        if workspace_id:
            query_filter = Filter(must=[
                FieldCondition(key="workspace_id", match=MatchValue(value=workspace_id))
            ])

        results = self.client.search(
            collection_name=self.collection,
            query_vector=query_embedding,
            query_filter=query_filter,
            limit=limit,
        )

        return [
            {
                "score": hit.score,
                "finding_id": hit.payload.get("finding_id"),
                "text": hit.payload.get("text", ""),
                **{k: v for k, v in hit.payload.items() if k not in ("finding_id", "text")},
            }
            for hit in results
        ]

    async def find_duplicates(
        self, embedding: list[float], threshold: float = 0.92
    ) -> list[dict[str, Any]]:
        """Find potentially duplicate findings based on semantic similarity."""
        results = await self.search(embedding, limit=5)
        return [r for r in results if r["score"] >= threshold]
