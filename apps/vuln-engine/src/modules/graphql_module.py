"""GraphQL Vulnerability Testing Module."""
from __future__ import annotations
from typing import Any
import httpx, json, structlog
from src.core.module_runner import VulnModule
logger = structlog.get_logger(__name__)

class GraphQLModule(VulnModule):
    name = "graphql_scanner"
    category = "graphql"
    description = "GraphQL introspection, injection, and authorization testing"

    INTROSPECTION_QUERY = '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

    async def test(self, target: str, params: dict, auth: Any = None,
                   hypothesis: dict | None = None) -> list[dict[str, Any]]:
        findings = []
        client = httpx.AsyncClient(timeout=15.0, verify=False)
        try:
            # Test introspection
            headers = {"Content-Type": "application/json"}
            resp = await client.post(target, content=self.INTROSPECTION_QUERY, headers=headers)
            if resp.status_code == 200 and "__schema" in resp.text:
                data = resp.json()
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                findings.append({
                    "title": "GraphQL introspection enabled",
                    "severity": "medium", "category": "graphql",
                    "affected_url": target, "confidence": 0.95,
                    "evidence": {"types_count": len(types), "introspection": True},
                    "source_tool": self.name,
                    "description": f"GraphQL introspection is enabled, exposing {len(types)} types",
                })

                # Check for sensitive types
                sensitive = [t["name"] for t in types if any(
                    kw in t["name"].lower() for kw in ["user", "admin", "secret", "token", "password", "credential"]
                )]
                if sensitive:
                    findings.append({
                        "title": f"Sensitive GraphQL types exposed: {', '.join(sensitive[:5])}",
                        "severity": "high", "category": "graphql",
                        "affected_url": target, "confidence": 0.8,
                        "evidence": {"sensitive_types": sensitive},
                        "source_tool": self.name,
                        "description": "GraphQL schema exposes potentially sensitive types",
                    })

            # Test for query depth/complexity limits
            deep_query = '{"query":"{ __typename ' + '{ __typename ' * 20 + '}' * 20 + '}"}'
            try:
                resp = await client.post(target, content=deep_query, headers=headers)
                if resp.status_code == 200:
                    findings.append({
                        "title": "No GraphQL query depth limit",
                        "severity": "medium", "category": "graphql",
                        "affected_url": target, "confidence": 0.7,
                        "evidence": {"depth_tested": 20, "status": resp.status_code},
                        "source_tool": self.name,
                        "description": "GraphQL endpoint accepts deeply nested queries (DoS risk)",
                    })
            except Exception:
                pass

        finally:
            await client.aclose()
        return findings
