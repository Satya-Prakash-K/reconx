"""Embedding Pipeline — semantic encoding for dedup, search, and RAG.

Uses sentence-transformers for local embedding generation
and Qdrant for vector storage and similarity search.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Optional

import numpy as np
import structlog

logger = structlog.get_logger(__name__)


class EmbeddingPipeline:
    """Generates and stores semantic embeddings for vulnerability findings."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self.model = None
        self.qdrant = None

    async def init(self):
        """Load embedding model and connect to Qdrant."""
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
            logger.info("Embedding model loaded", model=self.model_name)
        except Exception as e:
            logger.warning("Embedding model unavailable", error=str(e))

        try:
            from qdrant_client import QdrantClient
            from qdrant_client.http.models import Distance, VectorParams
            qdrant_url = os.getenv("QDRANT_URL", "http://localhost:6333")
            self.qdrant = QdrantClient(url=qdrant_url)

            # Create collections if they don't exist
            collections = [c.name for c in self.qdrant.get_collections().collections]
            for col_name in ["reconx_findings", "reconx_payloads", "reconx_reports"]:
                if col_name not in collections:
                    self.qdrant.create_collection(
                        collection_name=col_name,
                        vectors_config=VectorParams(size=384, distance=Distance.COSINE),
                    )
            logger.info("Qdrant connected", url=qdrant_url)
        except Exception as e:
            logger.warning("Qdrant unavailable", error=str(e))

    def embed(self, text: str) -> list[float] | None:
        """Generate embedding for a single text."""
        if not self.model:
            return None
        return self.model.encode(text).tolist()

    async def embed_batch(self, texts: list[str]) -> list[list[float]] | None:
        """Generate embeddings for a batch of texts."""
        if not self.model:
            return None
        return self.model.encode(texts).tolist()

    async def store_finding(self, finding: dict[str, Any]):
        """Store finding embedding in Qdrant for semantic search."""
        if not self.qdrant or not self.model:
            return

        text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('affected_url', '')}"
        vector = self.embed(text)
        if not vector:
            return

        from qdrant_client.http.models import PointStruct
        point_id = abs(hash(finding.get("id", ""))) % (2**63)

        self.qdrant.upsert(
            collection_name="reconx_findings",
            points=[PointStruct(
                id=point_id,
                vector=vector,
                payload={
                    "finding_id": finding.get("id", ""),
                    "title": finding.get("title", ""),
                    "category": finding.get("category", ""),
                    "severity": finding.get("severity", ""),
                    "affected_url": finding.get("affected_url", ""),
                    "workspace_id": finding.get("workspace_id", ""),
                },
            )],
        )

    async def search_similar(self, query: str, limit: int = 10, category: str | None = None) -> list[dict]:
        """Semantic search for similar findings."""
        if not self.qdrant or not self.model:
            return []

        vector = self.embed(query)
        if not vector:
            return []

        from qdrant_client.http.models import Filter, FieldCondition, MatchValue
        query_filter = None
        if category:
            query_filter = Filter(must=[FieldCondition(key="category", match=MatchValue(value=category))])

        results = self.qdrant.search(
            collection_name="reconx_findings",
            query_vector=vector,
            query_filter=query_filter,
            limit=limit,
        )
        return [{"score": r.score, **r.payload} for r in results]

    async def find_duplicates(self, finding: dict, threshold: float = 0.92) -> list[dict]:
        """Find semantically duplicate findings."""
        text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('affected_url', '')}"
        results = await self.search_similar(text, limit=5)
        return [r for r in results if r["score"] >= threshold and r.get("finding_id") != finding.get("id")]


class SemanticCorrelationEngine:
    """Correlates findings across workspaces and programs using semantic similarity."""

    def __init__(self, embedding_pipeline: EmbeddingPipeline):
        self.embeddings = embedding_pipeline

    async def correlate(self, finding: dict, cross_workspace: bool = True) -> list[dict]:
        """Find semantically correlated findings."""
        text = f"{finding.get('title', '')} {finding.get('category', '')} {finding.get('description', '')}"
        results = await self.embeddings.search_similar(text, limit=20)

        correlated = []
        for r in results:
            if not cross_workspace and r.get("workspace_id") == finding.get("workspace_id"):
                continue
            if r["score"] > 0.75:
                correlated.append({
                    "finding_id": r.get("finding_id"),
                    "title": r.get("title"),
                    "category": r.get("category"),
                    "severity": r.get("severity"),
                    "similarity": r["score"],
                    "workspace_id": r.get("workspace_id"),
                })
        return correlated
