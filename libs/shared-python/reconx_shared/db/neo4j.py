"""Neo4j graph database driver wrapper."""

from __future__ import annotations

import os
from typing import Any, Optional

from neo4j import AsyncGraphDatabase, AsyncDriver

import structlog

logger = structlog.get_logger(__name__)

_driver: AsyncDriver | None = None


def get_neo4j_driver() -> AsyncDriver:
    """Get or create the Neo4j async driver."""
    global _driver

    if _driver is None:
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "neo4j_password")

        _driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
        logger.info("Neo4j driver created", uri=uri)

    return _driver


class Neo4jManager:
    """High-level Neo4j operations for attack surface graphing."""

    def __init__(self, driver: AsyncDriver | None = None):
        self.driver = driver or get_neo4j_driver()

    async def init_schema(self) -> None:
        """Create constraints and indexes for the graph schema."""
        async with self.driver.session() as session:
            constraints = [
                "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.name IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (u:URL) REQUIRE u.value IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Technology) REQUIRE t.name IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Port) REQUIRE p.uid IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (b:Bucket) REQUIRE b.name IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE",
            ]
            for constraint in constraints:
                await session.run(constraint)

            logger.info("Neo4j schema initialized")

    async def add_domain(self, name: str, workspace_id: str, **props: Any) -> None:
        """Add a domain node."""
        async with self.driver.session() as session:
            await session.run(
                """
                MERGE (d:Domain {name: $name})
                SET d.workspace_id = $workspace_id,
                    d.updated_at = datetime(),
                    d += $props
                """,
                name=name, workspace_id=workspace_id, props=props,
            )

    async def add_subdomain(
        self, subdomain: str, parent_domain: str, workspace_id: str, **props: Any
    ) -> None:
        """Add a subdomain node and link to parent domain."""
        async with self.driver.session() as session:
            await session.run(
                """
                MERGE (s:Subdomain {name: $subdomain})
                SET s.workspace_id = $workspace_id,
                    s.updated_at = datetime(),
                    s += $props
                WITH s
                MERGE (d:Domain {name: $parent_domain})
                MERGE (s)-[:SUBDOMAIN_OF]->(d)
                """,
                subdomain=subdomain, parent_domain=parent_domain,
                workspace_id=workspace_id, props=props,
            )

    async def add_resolution(self, hostname: str, ip: str, **props: Any) -> None:
        """Add DNS resolution relationship."""
        async with self.driver.session() as session:
            await session.run(
                """
                MERGE (h:Subdomain {name: $hostname})
                MERGE (i:IP {address: $ip})
                MERGE (h)-[r:RESOLVES_TO]->(i)
                SET r.updated_at = datetime(), r += $props
                """,
                hostname=hostname, ip=ip, props=props,
            )

    async def add_port(self, ip: str, port: int, protocol: str = "tcp", **props: Any) -> None:
        """Add a port node and link to IP."""
        uid = f"{ip}:{port}/{protocol}"
        async with self.driver.session() as session:
            await session.run(
                """
                MERGE (i:IP {address: $ip})
                MERGE (p:Port {uid: $uid})
                SET p.port = $port, p.protocol = $protocol,
                    p.updated_at = datetime(), p += $props
                MERGE (i)-[:EXPOSES]->(p)
                """,
                ip=ip, uid=uid, port=port, protocol=protocol, props=props,
            )

    async def add_technology(self, hostname: str, technology: str, **props: Any) -> None:
        """Add technology detection relationship."""
        async with self.driver.session() as session:
            await session.run(
                """
                MERGE (h:Subdomain {name: $hostname})
                MERGE (t:Technology {name: $technology})
                MERGE (h)-[r:USES]->(t)
                SET r.updated_at = datetime(), r += $props
                """,
                hostname=hostname, technology=technology, props=props,
            )

    async def add_url(self, url: str, hostname: str, **props: Any) -> None:
        """Add a URL node linked to its host."""
        async with self.driver.session() as session:
            await session.run(
                """
                MERGE (u:URL {value: $url})
                SET u.updated_at = datetime(), u += $props
                WITH u
                MERGE (h:Subdomain {name: $hostname})
                MERGE (h)-[:HOSTS]->(u)
                """,
                url=url, hostname=hostname, props=props,
            )

    async def add_finding(
        self, finding_id: str, hostname: str, severity: str, title: str, **props: Any
    ) -> None:
        """Add a finding node linked to its target."""
        async with self.driver.session() as session:
            await session.run(
                """
                MERGE (f:Finding {id: $finding_id})
                SET f.title = $title, f.severity = $severity,
                    f.updated_at = datetime(), f += $props
                WITH f
                MERGE (h:Subdomain {name: $hostname})
                MERGE (f)-[:AFFECTS]->(h)
                """,
                finding_id=finding_id, hostname=hostname,
                severity=severity, title=title, props=props,
            )

    async def get_attack_surface(
        self, workspace_id: str, depth: int = 3
    ) -> list[dict[str, Any]]:
        """Get the full attack surface graph for a workspace."""
        async with self.driver.session() as session:
            result = await session.run(
                """
                MATCH (d:Domain {workspace_id: $workspace_id})
                CALL apoc.path.subgraphAll(d, {maxLevel: $depth})
                YIELD nodes, relationships
                RETURN nodes, relationships
                """,
                workspace_id=workspace_id, depth=depth,
            )
            records = [record.data() async for record in result]
            return records

    async def get_attack_paths(
        self, workspace_id: str, min_severity: str = "medium"
    ) -> list[dict[str, Any]]:
        """Find potential attack paths through the graph."""
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        min_score = severity_order.get(min_severity, 2)

        async with self.driver.session() as session:
            result = await session.run(
                """
                MATCH path = (d:Domain {workspace_id: $workspace_id})
                    -[:SUBDOMAIN_OF*0..1]-(s:Subdomain)
                    -[:RESOLVES_TO]->(i:IP)
                    -[:EXPOSES]->(p:Port)
                OPTIONAL MATCH (f:Finding)-[:AFFECTS]->(s)
                WHERE f.severity IN ['critical', 'high', 'medium']
                RETURN d.name AS domain,
                       s.name AS subdomain,
                       i.address AS ip,
                       p.port AS port,
                       collect(DISTINCT {
                           title: f.title,
                           severity: f.severity
                       }) AS findings
                ORDER BY size(findings) DESC
                LIMIT 100
                """,
                workspace_id=workspace_id,
            )
            records = [record.data() async for record in result]
            return records

    async def close(self) -> None:
        """Close the driver."""
        global _driver
        if self.driver:
            await self.driver.close()
            _driver = None
