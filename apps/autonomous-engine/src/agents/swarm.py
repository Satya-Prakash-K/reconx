"""Autonomous Agent Swarm — LangGraph-based multi-agent orchestration.

Implements a cyclic state machine where specialized agents collaborate:
  Planner → Recon → Analysis → Hypothesis → Testing → Triage → Report → Memory
                ↑                                                    |
                └────────────────── Continuous Loop ─────────────────┘

Each agent has:
- Dedicated role and capabilities
- Access to MCP tool registry
- Shared vector + graph memory
- Safety guardrails
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Annotated, Optional, TypedDict

import structlog

logger = structlog.get_logger(__name__)


# ── Swarm State ──────────────────────────────

class SwarmPhase(str, Enum):
    PLANNING = "planning"
    RECON = "recon"
    ANALYSIS = "analysis"
    HYPOTHESIS = "hypothesis"
    TESTING = "testing"
    TRIAGE = "triage"
    REPORTING = "reporting"
    MEMORY = "memory"
    COMPLETE = "complete"
    PAUSED = "paused"


class SwarmState(TypedDict):
    """Shared state flowing through the agent swarm."""
    session_id: str
    workspace_id: str
    targets: list[str]
    phase: str
    cycle: int
    max_cycles: int

    # Planner
    plan: dict[str, Any]
    priority_targets: list[str]

    # Recon
    discovered_endpoints: list[dict]
    discovered_assets: list[dict]
    changes_detected: list[dict]

    # Analysis
    classified_endpoints: list[dict]
    attack_surface: dict[str, Any]

    # Hypothesis
    hypotheses: list[dict]

    # Testing
    findings: list[dict]
    raw_results: list[dict]

    # Triage
    triaged_findings: list[dict]
    duplicates_removed: int

    # Reporting
    reports: list[dict]

    # Memory
    memory_updates: list[dict]

    # Meta
    reasoning_chain: list[str]
    errors: list[str]
    guardrail_violations: list[str]
    metrics: dict[str, Any]


def create_initial_state(workspace_id: str, targets: list[str], max_cycles: int = 5) -> SwarmState:
    return SwarmState(
        session_id=str(uuid.uuid4()),
        workspace_id=workspace_id,
        targets=targets,
        phase=SwarmPhase.PLANNING,
        cycle=0,
        max_cycles=max_cycles,
        plan={},
        priority_targets=[],
        discovered_endpoints=[],
        discovered_assets=[],
        changes_detected=[],
        classified_endpoints=[],
        attack_surface={},
        hypotheses=[],
        findings=[],
        raw_results=[],
        triaged_findings=[],
        duplicates_removed=0,
        reports=[],
        memory_updates=[],
        reasoning_chain=[],
        errors=[],
        guardrail_violations=[],
        metrics={"started_at": datetime.now(timezone.utc).isoformat()},
    )


# ── Agent Base ───────────────────────────────

class SwarmAgent:
    """Base class for all swarm agents."""

    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        self.agent_id = f"{name}-{uuid.uuid4().hex[:6]}"

    async def execute(self, state: SwarmState) -> SwarmState:
        raise NotImplementedError

    def _reason(self, state: SwarmState, message: str) -> SwarmState:
        state["reasoning_chain"].append(f"[{self.name}] {message}")
        return state


# ── Planner Agent ────────────────────────────

class PlannerAgent(SwarmAgent):
    """Creates and adapts the overall testing strategy."""

    def __init__(self):
        super().__init__("planner", "strategic_planning")

    async def execute(self, state: SwarmState) -> SwarmState:
        state["phase"] = SwarmPhase.PLANNING
        targets = state["targets"]
        cycle = state["cycle"]

        state = self._reason(state, f"Cycle {cycle}: Planning strategy for {len(targets)} targets")

        # Adaptive planning based on previous cycle results
        if cycle > 0 and state["findings"]:
            state = self._reason(state, f"Previous cycle found {len(state['findings'])} findings — focusing deeper")
            # Prioritize targets with confirmed vulns
            vuln_urls = {f.get("affected_url", "").split("?")[0] for f in state["findings"]}
            state["priority_targets"] = [t for t in targets if any(t in u for u in vuln_urls)]
        else:
            state["priority_targets"] = targets

        state["plan"] = {
            "cycle": cycle,
            "targets": len(targets),
            "priority_targets": len(state["priority_targets"]),
            "strategy": "deep_scan" if cycle > 2 else "broad_scan" if cycle == 0 else "focused_scan",
            "categories": ["xss", "sqli", "ssrf", "idor", "auth_flaw", "jwt_weakness",
                          "cors_misconfig", "data_exposure", "cloud_exposure", "graphql"],
            "enable_fuzzing": cycle >= 1,
            "enable_browser": cycle >= 1,
            "aggressive_mode": cycle >= 3,
        }

        state = self._reason(state, f"Strategy: {state['plan']['strategy']}")
        return state


# ── Recon Agent ──────────────────────────────

class ReconAgent(SwarmAgent):
    """Performs continuous reconnaissance and change detection."""

    def __init__(self):
        super().__init__("recon", "reconnaissance")

    async def execute(self, state: SwarmState) -> SwarmState:
        state["phase"] = SwarmPhase.RECON
        targets = state["priority_targets"] or state["targets"]

        state = self._reason(state, f"Scanning {len(targets)} targets for endpoints and assets")

        # Simulate endpoint discovery
        endpoints = []
        for target in targets:
            endpoints.extend([
                {"url": f"{target}/api/users", "method": "GET", "params": {"id": "1"}, "priority": 9},
                {"url": f"{target}/api/auth/login", "method": "POST", "params": {}, "priority": 10},
                {"url": f"{target}/graphql", "method": "POST", "params": {}, "priority": 8},
                {"url": f"{target}/api/files/upload", "method": "POST", "params": {}, "priority": 7},
                {"url": f"{target}/search", "method": "GET", "params": {"q": ""}, "priority": 6},
            ])

        state["discovered_endpoints"] = endpoints
        state = self._reason(state, f"Discovered {len(endpoints)} endpoints")
        return state


# ── Analysis Agent ───────────────────────────

class AnalysisAgent(SwarmAgent):
    """Classifies endpoints and builds attack surface model."""

    def __init__(self):
        super().__init__("analysis", "attack_surface_analysis")

    async def execute(self, state: SwarmState) -> SwarmState:
        state["phase"] = SwarmPhase.ANALYSIS
        endpoints = state["discovered_endpoints"]

        state = self._reason(state, f"Classifying {len(endpoints)} endpoints")

        classified = []
        for ep in endpoints:
            url = ep.get("url", "")
            classification = {
                **ep,
                "category": "api" if "/api/" in url else "graphql" if "graphql" in url else "web",
                "auth_required": "auth" in url or "admin" in url,
                "risk_score": ep.get("priority", 5),
                "technologies": [],
            }
            classified.append(classification)

        classified.sort(key=lambda x: x["risk_score"], reverse=True)
        state["classified_endpoints"] = classified
        state["attack_surface"] = {
            "total_endpoints": len(classified),
            "api_count": sum(1 for c in classified if c["category"] == "api"),
            "auth_endpoints": sum(1 for c in classified if c["auth_required"]),
            "high_priority": sum(1 for c in classified if c["risk_score"] >= 8),
        }

        state = self._reason(state, f"Attack surface: {state['attack_surface']}")
        return state


# ── Hypothesis Agent ─────────────────────────

class HypothesisAgent(SwarmAgent):
    """Generates vulnerability hypotheses using AI reasoning."""

    def __init__(self):
        super().__init__("hypothesis", "vulnerability_prediction")

    async def execute(self, state: SwarmState) -> SwarmState:
        state["phase"] = SwarmPhase.HYPOTHESIS
        endpoints = state["classified_endpoints"]

        state = self._reason(state, f"Generating hypotheses for {len(endpoints)} classified endpoints")

        hypotheses = []
        for ep in endpoints[:20]:
            url = ep.get("url", "")
            params = ep.get("params", {})

            if params:
                for param in params:
                    hypotheses.append({"url": url, "param": param, "category": "xss", "confidence": 0.7,
                                       "reasoning": f"Parameter '{param}' may reflect user input"})
                    hypotheses.append({"url": url, "param": param, "category": "sqli", "confidence": 0.6,
                                       "reasoning": f"Parameter '{param}' may be used in DB query"})
            if "graphql" in url:
                hypotheses.append({"url": url, "param": "", "category": "graphql", "confidence": 0.8,
                                   "reasoning": "GraphQL endpoint — check introspection, depth, batching"})
            if "auth" in url or "login" in url:
                hypotheses.append({"url": url, "param": "", "category": "auth_flaw", "confidence": 0.7,
                                   "reasoning": "Auth endpoint — check rate limiting, credential stuffing"})
            if "upload" in url:
                hypotheses.append({"url": url, "param": "", "category": "file_upload", "confidence": 0.8,
                                   "reasoning": "Upload endpoint — check file type restrictions"})

        state["hypotheses"] = hypotheses
        state = self._reason(state, f"Generated {len(hypotheses)} hypotheses")
        return state


# ── Risk Agent ───────────────────────────────

class RiskAgent(SwarmAgent):
    """Evaluates and prioritizes risk across findings."""

    def __init__(self):
        super().__init__("risk", "risk_assessment")

    async def execute(self, state: SwarmState) -> SwarmState:
        findings = state.get("triaged_findings", [])
        state = self._reason(state, f"Risk assessment across {len(findings)} findings")

        for f in findings:
            cvss = f.get("cvss_score", 0)
            exploit = f.get("exploitability_score", 0)
            impact = f.get("impact_score", 0)
            f["composite_risk"] = round(cvss * 0.4 + exploit * 0.3 + impact * 0.3, 1)

        findings.sort(key=lambda x: x.get("composite_risk", 0), reverse=True)
        state["triaged_findings"] = findings
        return state


# ── Memory Agent ─────────────────────────────

class MemoryAgent(SwarmAgent):
    """Stores learnings in long-term vector + graph memory."""

    def __init__(self):
        super().__init__("memory", "knowledge_persistence")

    async def execute(self, state: SwarmState) -> SwarmState:
        state["phase"] = SwarmPhase.MEMORY
        findings = state.get("triaged_findings", [])
        hypotheses = state.get("hypotheses", [])

        updates = []
        for f in findings:
            updates.append({"type": "finding", "data": f, "action": "store"})
        for h in [h for h in hypotheses if h.get("confirmed")]:
            updates.append({"type": "hypothesis_confirmed", "data": h, "action": "reinforce"})

        state["memory_updates"] = updates
        state = self._reason(state, f"Stored {len(updates)} items in long-term memory")

        # Decide whether to continue
        state["cycle"] += 1
        if state["cycle"] >= state["max_cycles"]:
            state["phase"] = SwarmPhase.COMPLETE
            state = self._reason(state, f"Max cycles ({state['max_cycles']}) reached — completing")
        else:
            state["phase"] = SwarmPhase.PLANNING
            state = self._reason(state, f"Starting cycle {state['cycle']}")

        state["metrics"]["completed_at"] = datetime.now(timezone.utc).isoformat()
        state["metrics"]["total_findings"] = len(state.get("findings", []))
        state["metrics"]["total_cycles"] = state["cycle"]
        return state


# ── Safety Guardrails ────────────────────────

class SafetyGuardrails:
    """Enforces AI safety policies throughout the swarm."""

    BLOCKED_ACTIONS = [
        "denial_of_service", "data_destruction", "privilege_escalation_live",
        "lateral_movement", "exfiltration", "ransomware",
    ]
    MAX_RPS = 50
    MAX_PAYLOAD_SIZE = 10000

    @staticmethod
    def validate_target(target: str, allowed_scopes: list[str]) -> bool:
        """Ensure target is within authorized scope."""
        from urllib.parse import urlparse
        parsed = urlparse(target)
        domain = parsed.hostname or ""
        return any(
            domain == scope or domain.endswith(f".{scope}")
            for scope in allowed_scopes
        )

    @staticmethod
    def validate_action(action: str) -> tuple[bool, str]:
        if action.lower() in SafetyGuardrails.BLOCKED_ACTIONS:
            return False, f"Blocked action: {action}"
        return True, ""

    @staticmethod
    def validate_payload(payload: str) -> tuple[bool, str]:
        if len(payload) > SafetyGuardrails.MAX_PAYLOAD_SIZE:
            return False, "Payload too large"
        dangerous = ["rm -rf", "DROP TABLE", "FORMAT C:", "shutdown", ":(){ :|:& };:"]
        for d in dangerous:
            if d.lower() in payload.lower():
                return False, f"Dangerous payload pattern: {d}"
        return True, ""
