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


def create_initial_state(workspace_id: str, session_id: str, targets: list[str], max_cycles: int = 5) -> SwarmState:
    return SwarmState(
        session_id=session_id,
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
    """Deep recursive crawler — 5 levels, forms, robots.txt, sitemap, JS endpoints."""

    def __init__(self):
        super().__init__("recon", "reconnaissance")

    # Common API paths to probe
    _API_PATHS = [
        "/api/", "/api/v1/", "/api/v2/", "/graphql", "/swagger.json",
        "/openapi.json", "/api-docs", "/.env", "/robots.txt", "/sitemap.xml",
        "/admin/", "/login", "/register", "/upload", "/search",
        "/api/users", "/api/auth", "/api/products", "/api/orders",
    ]
    _SKIP_EXTS = {'.css','.png','.jpg','.jpeg','.gif','.ico','.svg',
                  '.woff','.woff2','.ttf','.eot','.mp4','.mp3','.pdf','.zip'}

    async def execute(self, state: SwarmState) -> SwarmState:
        state["phase"] = SwarmPhase.RECON
        targets = state["priority_targets"] or state["targets"]
        state = self._reason(state, f"Scanning {len(targets)} targets for live endpoints and assets")

        import httpx, re
        from urllib.parse import urljoin, urlparse, parse_qs
        from collections import deque

        try:
            from bs4 import BeautifulSoup
            _bs4 = True
        except ImportError:
            _bs4 = False

        all_endpoints: list[dict] = []
        visited: set[str] = set()

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        async with httpx.AsyncClient(verify=False, timeout=12.0,
                                     follow_redirects=True, headers=headers) as client:
            for target in targets:
                if not target.startswith("http"):
                    target = f"http://{target}"
                base = urlparse(target)
                base_origin = f"{base.scheme}://{base.netloc}"
                base_domain = base.netloc
                endpoints: list[dict] = []

                state = self._reason(state, f"Crawling {target}")

                # ── robots.txt + sitemap ────────────────────────
                for path in ["/robots.txt", "/sitemap.xml"]:
                    try:
                        r = await client.get(base_origin + path)
                        if r.status_code == 200:
                            urls_found = re.findall(r'https?://[^\s<>"\']+', r.text)
                            disallows = re.findall(r'Disallow:\s*(\S+)', r.text)
                            for u in urls_found + [base_origin + d for d in disallows]:
                                if base_domain in u:
                                    visited.add(u)
                                    pq = urlparse(u)
                                    params = {k: v[0] for k, v in parse_qs(pq.query).items()}
                                    endpoints.append({"url": u.split("?")[0], "method": "GET",
                                                      "params": params, "source": "robots/sitemap",
                                                      "priority": 7 if params else 5})
                    except Exception:
                        pass

                # ── Probe common API paths ──────────────────────
                for api_path in self._API_PATHS:
                    url = base_origin + api_path
                    if url not in visited:
                        try:
                            r = await client.get(url)
                            if r.status_code in (200, 201, 301, 302, 403, 405):
                                visited.add(url)
                                endpoints.append({"url": url, "method": "GET", "params": {},
                                                  "source": "api_probe", "priority": 8,
                                                  "status": r.status_code})
                        except Exception:
                            pass

                # ── BFS 5-level crawler ─────────────────────────
                queue: deque[tuple[str, int]] = deque([(target, 0)])
                visited.add(target)

                while queue:
                    current_url, depth = queue.popleft()
                    if depth > 5:
                        continue
                    try:
                        resp = await client.get(current_url)
                        content_type = resp.headers.get("content-type", "")

                        # ── JS endpoint extraction ──────────────
                        if "javascript" in content_type:
                            js_urls = re.findall(
                                r'["\'](/(?:api|v\d|graphql|admin|auth|user|search|upload)[^"\'?\s]{0,80})',
                                resp.text)
                            for ju in js_urls:
                                full = base_origin + ju
                                if full not in visited:
                                    visited.add(full)
                                    endpoints.append({"url": full, "method": "GET", "params": {},
                                                      "source": "js_extraction", "priority": 8})
                            continue

                        if "html" not in content_type and depth > 0:
                            continue

                        # ── HTML parsing ────────────────────────
                        if _bs4:
                            soup = BeautifulSoup(resp.text, "lxml")
                            # Forms
                            for form in soup.find_all("form"):
                                action = form.get("action", "")
                                method = (form.get("method") or "GET").upper()
                                form_url = urljoin(str(resp.url), action) if action else str(resp.url)
                                if urlparse(form_url).netloc == base_domain:
                                    inputs = {
                                        inp.get("name"): inp.get("value", "")
                                        for inp in form.find_all("input")
                                        if inp.get("name")
                                    }
                                    if form_url not in visited:
                                        visited.add(form_url)
                                        endpoints.append({"url": form_url, "method": method,
                                                          "params": inputs, "source": "form",
                                                          "priority": 9 if inputs else 6})
                            # Links
                            raw_links = [a.get("href","") for a in soup.find_all("a", href=True)]
                            raw_links += [s.get("src","") for s in soup.find_all("script", src=True)]
                        else:
                            raw_links = re.findall(r'href=[\'"]?([^\'" >]+)', resp.text)
                            raw_links += re.findall(r'action=[\'"]?([^\'" >]+)', resp.text)
                            raw_links += re.findall(r'src=[\'"]?([^\'" >]+\.js[^\'" >]*)', resp.text)

                        for link in raw_links:
                            if not link or link.startswith(("#","mailto:","javascript:","tel:")):
                                continue
                            full_url = urljoin(str(resp.url), link)
                            parsed = urlparse(full_url)
                            if parsed.netloc != base_domain:
                                continue
                            ext = "." + full_url.rsplit(".", 1)[-1].split("?")[0].lower() if "." in full_url else ""
                            if ext in self._SKIP_EXTS:
                                # Still queue JS files for endpoint extraction
                                if full_url.endswith(".js") and full_url not in visited:
                                    visited.add(full_url)
                                    queue.append((full_url, depth + 1))
                                continue
                            if full_url not in visited:
                                visited.add(full_url)
                                params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                                endpoints.append({
                                    "url": full_url.split("?")[0],
                                    "method": "GET",
                                    "params": params,
                                    "source": "crawler",
                                    "priority": 9 if params else 5
                                })
                                if depth < 5:
                                    queue.append((full_url, depth + 1))

                    except Exception:
                        pass

                state = self._reason(state, f"Found {len(endpoints)} endpoints from {target}")
                all_endpoints.extend(endpoints)

        # Deduplicate by URL
        seen_urls: set[str] = set()
        deduped = []
        for ep in all_endpoints:
            if ep["url"] not in seen_urls:
                seen_urls.add(ep["url"])
                deduped.append(ep)

        state["discovered_endpoints"] = deduped
        state = self._reason(state, f"Total discovered {len(deduped)} unique endpoints")
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
        policy = state.get("policy", {})
        allowed = policy.get("allowed_tests", [
            "xss","sqli","lfi","ssrf","csrf","cors","idor",
            "open_redirect","ssti","xxe","cmdi","misconfig","graphql","jwt"
        ])

        state = self._reason(state, f"Generating hypotheses for {len(endpoints)} classified endpoints")

        hypotheses = []
        for ep in endpoints[:50]:  # cap at 50 to avoid explosion
            url = ep.get("url", "")
            params = ep.get("params", {})
            method = ep.get("method", "GET")
            source = ep.get("source", "")
            lower_url = url.lower()

            for param in params:
                pl = param.lower()
                # Injection tests for every parameter
                if "xss" in allowed:
                    hypotheses.append({"url": url, "param": param, "method": method,
                        "category": "xss", "confidence": 0.7,
                        "reasoning": f"Param '{param}' may reflect input in HTML"})
                if "sqli" in allowed:
                    hypotheses.append({"url": url, "param": param, "method": method,
                        "category": "sqli", "confidence": 0.65,
                        "reasoning": f"Param '{param}' may be used in SQL query"})
                if "ssti" in allowed:
                    hypotheses.append({"url": url, "param": param, "method": method,
                        "category": "ssti", "confidence": 0.5,
                        "reasoning": f"Param '{param}' may be passed to a template engine"})
                # File/path params → LFI
                if any(k in pl for k in ["page","file","path","include","doc","template","load","read"]):
                    if "lfi" in allowed:
                        hypotheses.append({"url": url, "param": param, "method": method,
                            "category": "lfi", "confidence": 0.8,
                            "reasoning": f"Param '{param}' looks like a file include"})
                # URL/redirect params → SSRF + Open Redirect
                if any(k in pl for k in ["url","redirect","next","return","target","src","dest","callback","redir"]):
                    if "ssrf" in allowed:
                        hypotheses.append({"url": url, "param": param, "method": method,
                            "category": "ssrf", "confidence": 0.75,
                            "reasoning": f"Param '{param}' may trigger server-side fetch"})
                    if "open_redirect" in allowed:
                        hypotheses.append({"url": url, "param": param, "method": method,
                            "category": "open_redirect", "confidence": 0.75,
                            "reasoning": f"Param '{param}' may redirect to arbitrary URL"})
                # ID params → IDOR
                if any(k in pl for k in ["id","user","uid","account","order","item","record"]):
                    if "idor" in allowed:
                        hypotheses.append({"url": url, "param": param, "method": method,
                            "category": "idor", "confidence": 0.65,
                            "reasoning": f"Param '{param}' may expose other users' data via ID change"})
                # Command-like params → CMDi (aggressive)
                if any(k in pl for k in ["cmd","exec","command","ping","host","ip","query","run"]):
                    if "cmdi" in allowed:
                        hypotheses.append({"url": url, "param": param, "method": method,
                            "category": "cmdi", "confidence": 0.7,
                            "reasoning": f"Param '{param}' may be passed to OS command"})

            # Per-endpoint checks (no param needed)
            # CSRF — any form endpoint
            if source == "form" and method == "POST" and "csrf" in allowed:
                hypotheses.append({"url": url, "param": "", "method": method,
                    "category": "csrf", "confidence": 0.7,
                    "reasoning": "POST form — check for missing CSRF token"})
            # CORS
            if "cors" in allowed:
                hypotheses.append({"url": url, "param": "", "method": "GET",
                    "category": "cors", "confidence": 0.6,
                    "reasoning": "Check CORS headers for wildcard or reflection"})
            # GraphQL
            if "graphql" in lower_url and "graphql" in allowed:
                hypotheses.append({"url": url, "param": "", "method": "POST",
                    "category": "graphql", "confidence": 0.85,
                    "reasoning": "GraphQL endpoint — check introspection + batching"})
            # JWT
            if any(k in lower_url for k in ["auth","login","token","jwt"]) and "jwt" in allowed:
                hypotheses.append({"url": url, "param": "", "method": method,
                    "category": "jwt", "confidence": 0.6,
                    "reasoning": "Auth endpoint — check JWT algorithm confusion"})
            # Sensitive file exposure
            if any(url.endswith(p) for p in ["/.env","/.git/config","/backup.zip","/phpinfo.php"]):
                hypotheses.append({"url": url, "param": "", "method": "GET",
                    "category": "misconfig", "confidence": 0.9,
                    "reasoning": "Sensitive file path detected"})

        # Deduplicate
        seen = set()
        deduped = []
        for h in hypotheses:
            key = (h["url"], h["param"], h["category"])
            if key not in seen:
                seen.add(key)
                deduped.append(h)

        state["hypotheses"] = deduped
        state = self._reason(state, f"Generated {len(deduped)} hypotheses across {len(set(h['category'] for h in deduped))} vuln categories")
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
