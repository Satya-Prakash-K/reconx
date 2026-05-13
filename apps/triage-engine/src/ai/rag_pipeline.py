"""RAG Pipeline — Retrieval-Augmented Generation for exploit intelligence.

Combines:
- Qdrant (semantic vector search)
- Elasticsearch (full-text keyword search)
- Neo4j (graph relationship queries)
- Multi-model LLM (answer synthesis)
"""

from __future__ import annotations

import os
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class RAGPipeline:
    """Hybrid RAG pipeline combining vector, keyword, and graph retrieval."""

    def __init__(self):
        self.embedding_pipeline = None
        self.knowledge_graph = None
        self.llm = None

    async def init(self):
        from src.ai.embeddings import EmbeddingPipeline
        from src.knowledge.graph import KnowledgeGraph
        from src.ai.llm_gateway import MultiModelGateway

        self.embedding_pipeline = EmbeddingPipeline()
        await self.embedding_pipeline.init()
        self.knowledge_graph = KnowledgeGraph()
        await self.knowledge_graph.init()
        self.llm = MultiModelGateway()

    async def query(self, question: str, context: dict | None = None) -> dict[str, Any]:
        """Answer a question using hybrid retrieval + LLM synthesis."""
        # Stage 1: Retrieve from all sources
        vector_results = await self._search_qdrant(question)
        text_results = await self._search_elasticsearch(question)
        graph_results = await self._search_neo4j(question, context)

        # Stage 2: Merge and rank results
        all_context = self._merge_results(vector_results, text_results, graph_results)

        # Stage 3: Synthesize answer with LLM
        answer = await self._synthesize(question, all_context)

        return {
            "answer": answer,
            "sources": {
                "vector": len(vector_results),
                "text": len(text_results),
                "graph": len(graph_results),
            },
            "context_used": len(all_context),
        }

    async def get_exploit_intel(self, category: str, url: str = "") -> dict[str, Any]:
        """Get exploit intelligence for a vulnerability category and target."""
        # Vector: similar historical findings
        similar = await self.embedding_pipeline.search_similar(
            f"{category} vulnerability at {url}", limit=10, category=category
        ) if self.embedding_pipeline else []

        # Graph: effective payloads and tech correlations
        payloads = await self.knowledge_graph.get_effective_payloads(category) if self.knowledge_graph else []
        cross_intel = await self.knowledge_graph.get_cross_program_intel(category) if self.knowledge_graph else []

        # LLM: synthesize recommendations
        context_text = "\n".join([
            f"- {s.get('title', '')} (severity: {s.get('severity', '')})" for s in similar[:5]
        ])
        payload_text = "\n".join([f"- {p.get('payload', '')[:100]}" for p in payloads[:5]])

        recommendation = ""
        if self.llm:
            try:
                recommendation = await self.llm.generate(
                    f"Based on historical findings and effective payloads, provide testing "
                    f"recommendations for {category} vulnerabilities at {url}.\n\n"
                    f"Similar findings:\n{context_text}\n\n"
                    f"Effective payloads:\n{payload_text}",
                    task_type="analysis", max_tokens=500,
                )
            except Exception:
                pass

        return {
            "category": category,
            "similar_findings": similar,
            "effective_payloads": payloads,
            "technology_correlations": cross_intel,
            "ai_recommendation": recommendation,
        }

    async def _search_qdrant(self, query: str) -> list[dict]:
        if not self.embedding_pipeline:
            return []
        return await self.embedding_pipeline.search_similar(query, limit=10)

    async def _search_elasticsearch(self, query: str) -> list[dict]:
        try:
            from elasticsearch import AsyncElasticsearch
            es_url = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
            es = AsyncElasticsearch(es_url)
            result = await es.search(index="reconx_vuln_findings", body={
                "query": {"multi_match": {"query": query, "fields": ["title", "description", "category"]}},
                "size": 10,
            })
            await es.close()
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception:
            return []

    async def _search_neo4j(self, query: str, context: dict | None = None) -> list[dict]:
        if not self.knowledge_graph:
            return []
        category = context.get("category", "") if context else ""
        if category:
            return await self.knowledge_graph.find_similar_findings(category)
        return []

    def _merge_results(self, vector: list, text: list, graph: list) -> list[dict]:
        """Merge and deduplicate results from all sources."""
        seen = set()
        merged = []
        for source, results in [("vector", vector), ("text", text), ("graph", graph)]:
            for r in results:
                key = r.get("finding_id") or r.get("id") or r.get("title", "")
                if key not in seen:
                    seen.add(key)
                    merged.append({**r, "source": source})
        return merged[:20]

    async def _synthesize(self, question: str, context: list[dict]) -> str:
        """Use LLM to synthesize an answer from retrieved context."""
        if not self.llm:
            return "RAG synthesis unavailable — no LLM configured."

        context_text = "\n".join([
            f"- [{c.get('source', 'unknown')}] {c.get('title', '')} "
            f"(severity: {c.get('severity', 'N/A')}, category: {c.get('category', 'N/A')})"
            for c in context[:10]
        ])

        return await self.llm.generate(
            f"Based on the following security intelligence context, answer this question:\n\n"
            f"Question: {question}\n\n"
            f"Context:\n{context_text}\n\n"
            f"Provide a concise, actionable answer.",
            task_type="reasoning", max_tokens=500,
        )
