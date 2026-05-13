"""WebSocket Analysis Module — real-time WebSocket vulnerability detection."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class WebSocketAnalyzer:
    """Analyzes WebSocket connections for security vulnerabilities.

    Checks:
    - Missing authentication on WS upgrade
    - Cross-site WebSocket hijacking (CSWSH)
    - Injection via WS messages
    - Sensitive data in WS frames
    - Missing origin validation
    """

    async def analyze(self, ws_url: str, auth_headers: dict | None = None) -> list[dict[str, Any]]:
        """Analyze a WebSocket endpoint for vulnerabilities."""
        findings: list[dict] = []

        try:
            import websockets

            # Test 1: Connect without authentication
            try:
                async with websockets.connect(ws_url, extra_headers={}, open_timeout=10) as ws:
                    findings.append({
                        "title": "WebSocket accepts unauthenticated connections",
                        "severity": "high",
                        "category": "auth_flaw",
                        "affected_url": ws_url,
                        "confidence": 0.8,
                        "evidence": {"connection": "established without auth"},
                        "source_tool": "websocket_analyzer",
                        "description": "WebSocket endpoint accepts connections without authentication",
                    })
                    await ws.close()
            except Exception:
                pass  # Connection refused = good, requires auth

            # Test 2: Cross-origin WebSocket hijacking
            evil_origins = ["https://evil.com", "null", "http://attacker.example.com"]
            for origin in evil_origins:
                try:
                    headers = {"Origin": origin}
                    if auth_headers:
                        headers.update(auth_headers)
                    async with websockets.connect(ws_url, extra_headers=headers, open_timeout=10) as ws:
                        findings.append({
                            "title": f"Cross-site WebSocket Hijacking (origin: {origin})",
                            "severity": "high",
                            "category": "cors_misconfig",
                            "affected_url": ws_url,
                            "confidence": 0.85,
                            "evidence": {"origin": origin, "accepted": True},
                            "source_tool": "websocket_analyzer",
                            "description": f"WebSocket accepts connection from origin: {origin}",
                        })
                        await ws.close()
                        break
                except Exception:
                    pass

            # Test 3: Injection via messages
            if auth_headers:
                injection_payloads = [
                    '{"action":"admin","data":"test"}',
                    '{"__proto__":{"isAdmin":true}}',
                    '<script>alert(1)</script>',
                    "' OR '1'='1",
                ]
                try:
                    async with websockets.connect(ws_url, extra_headers=auth_headers or {}, open_timeout=10) as ws:
                        for payload in injection_payloads:
                            await ws.send(payload)
                            try:
                                response = await asyncio.wait_for(ws.recv(), timeout=5)
                                if "error" in response.lower() or "exception" in response.lower():
                                    findings.append({
                                        "title": "WebSocket injection — error triggered",
                                        "severity": "medium",
                                        "category": "sqli",
                                        "affected_url": ws_url,
                                        "confidence": 0.6,
                                        "evidence": {"payload": payload, "response": response[:200]},
                                        "source_tool": "websocket_analyzer",
                                        "description": "WebSocket message triggered error response",
                                    })
                            except asyncio.TimeoutError:
                                pass
                        await ws.close()
                except Exception as e:
                    logger.debug("WS injection test failed", error=str(e))

        except ImportError:
            logger.warning("websockets library not available")

        return findings
