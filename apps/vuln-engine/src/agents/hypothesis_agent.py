"""Vulnerability Hypothesis Agent — AI-powered vulnerability prediction.

Uses LLM analysis to generate educated hypotheses about what vulnerabilities
might exist at specific endpoints based on:
- Parameter names and types
- Technology stack
- Endpoint patterns
- Historical vulnerability data
- Business logic indicators
"""

from __future__ import annotations

import json
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class VulnHypothesisAgent:
    """LLM-powered agent that generates vulnerability hypotheses.

    Given endpoint classifications and context, the agent predicts
    likely vulnerabilities and generates targeted testing strategies.
    """

    HYPOTHESIS_PROMPT = """You are an expert penetration tester. Analyze these endpoints and generate vulnerability hypotheses.

For each hypothesis, provide:
1. The specific vulnerability type (XSS, SQLi, SSRF, IDOR, etc.)
2. Which parameter is likely vulnerable
3. Why you believe this vulnerability exists
4. Suggested test payloads
5. Confidence level (0.0 - 1.0)

Endpoints:
{endpoints}

Technology Stack: {tech_stack}
Risk Indicators: {risk_indicators}

Return a JSON array of hypotheses:
[{{
    "endpoint_url": "...",
    "param": "parameter_name",
    "category": "xss|sqli|ssrf|idor|auth_flaw|...",
    "reasoning": "Why this is likely vulnerable",
    "test_strategy": "How to test this",
    "payloads": ["payload1", "payload2"],
    "confidence": 0.7,
    "severity_estimate": "high"
}}]

Focus on HIGH-IMPACT findings. Prioritize:
- SQL Injection in ID/filter parameters
- IDOR in resource-access endpoints
- SSRF in URL/fetch parameters
- XSS in search/display parameters
- Authentication bypasses in auth endpoints
"""

    async def generate_hypotheses(
        self,
        classifications: dict[str, Any],
        categories: list,
    ) -> list[dict[str, Any]]:
        """Generate vulnerability hypotheses using LLM analysis."""
        try:
            from apps.ai_engine.src.llm import get_llm_gateway
            llm = get_llm_gateway()
        except ImportError:
            # Fallback: use direct HTTP call to Ollama/OpenAI
            return await self._generate_heuristic_hypotheses(classifications)

        endpoints = classifications.get("endpoints", [])[:30]
        tech_stack = classifications.get("technologies", [])
        risk_indicators = []
        for ep in endpoints:
            risk_indicators.extend(ep.get("risk_indicators", []))

        prompt = self.HYPOTHESIS_PROMPT.format(
            endpoints=json.dumps(endpoints[:15], indent=2),
            tech_stack=", ".join(tech_stack[:20]),
            risk_indicators=", ".join(set(risk_indicators))[:500],
        )

        try:
            response = await llm.generate(prompt, temperature=0.3, max_tokens=4096)
            hypotheses = json.loads(response)
            if isinstance(hypotheses, list):
                logger.info("AI hypotheses generated", count=len(hypotheses))
                return hypotheses
        except (json.JSONDecodeError, Exception) as e:
            logger.warning("LLM hypothesis generation failed, using heuristics", error=str(e))

        return await self._generate_heuristic_hypotheses(classifications)

    async def _generate_heuristic_hypotheses(
        self, classifications: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Fallback: generate hypotheses using heuristic rules."""
        hypotheses: list[dict[str, Any]] = []
        endpoints = classifications.get("endpoints", [])

        PARAM_VULN_MAP = {
            "id": ("idor", 0.8, "high"), "user_id": ("idor", 0.8, "high"),
            "uid": ("idor", 0.8, "high"), "account": ("idor", 0.7, "high"),
            "url": ("ssrf", 0.7, "high"), "redirect": ("open_redirect", 0.8, "medium"),
            "next": ("open_redirect", 0.8, "medium"), "callback": ("open_redirect", 0.7, "medium"),
            "search": ("xss", 0.7, "medium"), "q": ("sqli", 0.6, "critical"),
            "query": ("sqli", 0.7, "critical"), "filter": ("sqli", 0.6, "high"),
            "sort": ("sqli", 0.5, "high"), "order": ("sqli", 0.5, "high"),
            "file": ("lfi", 0.7, "critical"), "path": ("lfi", 0.6, "critical"),
            "template": ("ssti", 0.6, "critical"), "page": ("sqli", 0.5, "high"),
            "token": ("jwt_weakness", 0.5, "high"), "jwt": ("jwt_weakness", 0.7, "high"),
        }

        for ep in endpoints[:50]:
            for param in ep.get("params", {}):
                param_lower = param.lower()
                for key, (cat, conf, sev) in PARAM_VULN_MAP.items():
                    if key in param_lower:
                        hypotheses.append({
                            "endpoint_url": ep.get("url", ""),
                            "param": param,
                            "category": cat,
                            "reasoning": f"Parameter '{param}' matches pattern for {cat}",
                            "confidence": conf,
                            "severity_estimate": sev,
                            "target": ep.get("url", ""),
                        })
                        break

        logger.info("Heuristic hypotheses generated", count=len(hypotheses))
        return hypotheses
