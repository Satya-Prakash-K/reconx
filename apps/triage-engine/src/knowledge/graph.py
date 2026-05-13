"""Knowledge Graph — Neo4j-based exploit intelligence and relationship memory.

Stores and queries:
- Historical findings and exploit patterns
- Vulnerability → Endpoint → Technology relationships
- Payload effectiveness tracking
- WAF fingerprint memory
- Cross-program correlation
- Attack chain relationships
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Optional

import structlog

logger = structlog.get_logger(__name__)


class KnowledgeGraph:
    """Neo4j-backed exploit intelligence knowledge graph."""

    def __init__(self, uri: str | None = None, user: str | None = None, password: str | None = None):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD", "neo4j_password")
        self.driver = None

    async def init(self):
        """Initialize Neo4j connection and create schema."""
        from neo4j import AsyncGraphDatabase
        self.driver = AsyncGraphDatabase.driver(self.uri, auth=(self.user, self.password))
        await self._create_schema()
        logger.info("Knowledge graph initialized", uri=self.uri)

    async def _create_schema(self):
        """Create indexes and constraints."""
        async with self.driver.session() as session:
            await session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE")
            await session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.url IS UNIQUE")
            await session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (t:Technology) REQUIRE t.name IS UNIQUE")
            await session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (c:CWE) REQUIRE c.id IS UNIQUE")
            await session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (p:Payload) REQUIRE p.hash IS UNIQUE")
            await session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (w:WAF) REQUIRE w.name IS UNIQUE")
            await session.run("CREATE INDEX IF NOT EXISTS FOR (f:Finding) ON (f.category)")
            await session.run("CREATE INDEX IF NOT EXISTS FOR (f:Finding) ON (f.severity)")

    # ── Store operations ─────────────────────

    async def store_finding(self, finding: dict[str, Any]):
        """Store a finding and its relationships in the graph."""
        async with self.driver.session() as session:
            # Create Finding node
            await session.run("""
                MERGE (f:Finding {id: $id})
                SET f.title = $title, f.category = $category, f.severity = $severity,
                    f.cvss = $cvss, f.confidence = $confidence, f.cwe_id = $cwe_id,
                    f.workspace_id = $workspace_id, f.source_tool = $source_tool,
                    f.created_at = datetime()
            """, id=finding.get("id", ""), title=finding.get("title", ""),
                category=finding.get("category", ""), severity=finding.get("severity", ""),
                cvss=finding.get("cvss_score", 0), confidence=finding.get("confidence", 0),
                cwe_id=finding.get("cwe_id", ""), workspace_id=finding.get("workspace_id", ""),
                source_tool=finding.get("source_tool", ""))

            # Create Endpoint node and relationship
            url = finding.get("affected_url", "")
            if url:
                await session.run("""
                    MERGE (e:Endpoint {url: $url})
                    WITH e
                    MATCH (f:Finding {id: $fid})
                    MERGE (f)-[:AFFECTS]->(e)
                """, url=url, fid=finding.get("id", ""))

            # Create CWE relationship
            cwe = finding.get("cwe_id", "")
            if cwe:
                await session.run("""
                    MERGE (c:CWE {id: $cwe_id})
                    SET c.name = $cwe_name
                    WITH c
                    MATCH (f:Finding {id: $fid})
                    MERGE (f)-[:CLASSIFIED_AS]->(c)
                """, cwe_id=cwe, cwe_name=finding.get("cwe_name", ""), fid=finding.get("id", ""))

            # Store payload effectiveness
            payload = finding.get("evidence", {}).get("payload", "")
            if payload:
                import hashlib
                p_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
                await session.run("""
                    MERGE (p:Payload {hash: $hash})
                    SET p.content = $content, p.category = $category
                    WITH p
                    MATCH (f:Finding {id: $fid})
                    MERGE (f)-[:USED_PAYLOAD]->(p)
                """, hash=p_hash, content=payload[:500], category=finding.get("category", ""),
                    fid=finding.get("id", ""))

        logger.debug("Finding stored in knowledge graph", id=finding.get("id", ""))

    async def store_waf_fingerprint(self, url: str, waf_name: str, bypassed: bool, payload: str = ""):
        """Track WAF encounters and bypass success."""
        async with self.driver.session() as session:
            await session.run("""
                MERGE (w:WAF {name: $name})
                MERGE (e:Endpoint {url: $url})
                MERGE (e)-[r:PROTECTED_BY]->(w)
                SET r.bypassed = $bypassed, r.last_seen = datetime()
            """, name=waf_name, url=url, bypassed=bypassed)

            if bypassed and payload:
                import hashlib
                p_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
                await session.run("""
                    MERGE (p:Payload {hash: $hash})
                    SET p.content = $content
                    WITH p
                    MATCH (w:WAF {name: $wname})
                    MERGE (p)-[:BYPASSES]->(w)
                """, hash=p_hash, content=payload[:500], wname=waf_name)

    async def store_technology(self, url: str, technologies: list[str]):
        """Store technology stack for an endpoint."""
        async with self.driver.session() as session:
            for tech in technologies:
                await session.run("""
                    MERGE (t:Technology {name: $tech})
                    MERGE (e:Endpoint {url: $url})
                    MERGE (e)-[:USES]->(t)
                """, tech=tech, url=url)

    # ── Query operations ─────────────────────

    async def find_similar_findings(self, category: str, url_pattern: str = "", limit: int = 10) -> list[dict]:
        """Find historically similar findings for correlation."""
        async with self.driver.session() as session:
            result = await session.run("""
                MATCH (f:Finding {category: $category})
                WHERE f.severity IN ['critical', 'high']
                OPTIONAL MATCH (f)-[:AFFECTS]->(e:Endpoint)
                RETURN f.id AS id, f.title AS title, f.severity AS severity,
                       f.cvss AS cvss, e.url AS url, f.source_tool AS tool
                ORDER BY f.cvss DESC
                LIMIT $limit
            """, category=category, limit=limit)
            return [dict(record) async for record in result]

    async def get_effective_payloads(self, category: str, waf_name: str = "") -> list[dict]:
        """Get historically effective payloads for a vulnerability category."""
        async with self.driver.session() as session:
            if waf_name:
                result = await session.run("""
                    MATCH (p:Payload {category: $category})-[:BYPASSES]->(w:WAF {name: $waf})
                    RETURN p.content AS payload, p.hash AS hash
                    LIMIT 20
                """, category=category, waf=waf_name)
            else:
                result = await session.run("""
                    MATCH (f:Finding {category: $category})-[:USED_PAYLOAD]->(p:Payload)
                    WHERE f.severity IN ['critical', 'high']
                    RETURN DISTINCT p.content AS payload, p.hash AS hash, count(f) AS success_count
                    ORDER BY success_count DESC
                    LIMIT 20
                """, category=category)
            return [dict(record) async for record in result]

    async def get_attack_chains(self, workspace_id: str) -> list[dict]:
        """Get vulnerability chains (findings that connect to same endpoint/service)."""
        async with self.driver.session() as session:
            result = await session.run("""
                MATCH (f1:Finding {workspace_id: $wid})-[:AFFECTS]->(e:Endpoint)<-[:AFFECTS]-(f2:Finding)
                WHERE f1.id < f2.id
                RETURN f1.title AS finding1, f2.title AS finding2, e.url AS endpoint,
                       f1.severity AS sev1, f2.severity AS sev2
                ORDER BY f1.cvss + f2.cvss DESC
                LIMIT 20
            """, wid=workspace_id)
            return [dict(record) async for record in result]

    async def get_cross_program_intel(self, category: str) -> list[dict]:
        """Get cross-program intelligence for a vulnerability category."""
        async with self.driver.session() as session:
            result = await session.run("""
                MATCH (f:Finding {category: $cat})-[:AFFECTS]->(e:Endpoint)
                OPTIONAL MATCH (e)-[:USES]->(t:Technology)
                WITH t.name AS tech, count(f) AS vuln_count, avg(f.cvss) AS avg_cvss
                WHERE tech IS NOT NULL
                RETURN tech, vuln_count, round(avg_cvss * 10) / 10 AS avg_cvss
                ORDER BY vuln_count DESC
                LIMIT 15
            """, cat=category)
            return [dict(record) async for record in result]

    async def get_endpoint_history(self, url: str) -> list[dict]:
        """Get full vulnerability history for an endpoint."""
        async with self.driver.session() as session:
            result = await session.run("""
                MATCH (e:Endpoint {url: $url})
                OPTIONAL MATCH (f:Finding)-[:AFFECTS]->(e)
                OPTIONAL MATCH (e)-[:USES]->(t:Technology)
                OPTIONAL MATCH (e)-[:PROTECTED_BY]->(w:WAF)
                RETURN collect(DISTINCT {title: f.title, severity: f.severity, cvss: f.cvss}) AS findings,
                       collect(DISTINCT t.name) AS technologies,
                       collect(DISTINCT w.name) AS wafs
            """, url=url)
            return [dict(record) async for record in result]

    async def close(self):
        if self.driver:
            await self.driver.close()
