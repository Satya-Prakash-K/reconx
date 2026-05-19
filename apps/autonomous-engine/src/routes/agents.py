"""Agent swarm API routes — with direct WebSocket streaming."""

from __future__ import annotations
import asyncio
import uuid
from typing import Any

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

router = APIRouter()
_logger = structlog.get_logger(__name__)

# ── In-memory session store ─────────────────────────────────────────────────
# Maps session_id → latest state snapshot for REST polling
_sessions: dict[str, dict[str, Any]] = {}
# Maps session_id → list of connected WebSocket clients
_ws_clients: dict[str, list[WebSocket]] = {}


class SessionRequest(BaseModel):
    workspace_id: str
    targets: list[str]
    max_cycles: int = 3
    mode: str = "autonomous"


# ── Broadcast helper ────────────────────────────────────────────────────────

async def _broadcast(session_id: str, state: dict[str, Any]) -> None:
    """Push state snapshot to all connected WebSocket clients for a session."""
    _sessions[session_id] = state
    dead = []
    for ws in _ws_clients.get(session_id, []):
        try:
            await ws.send_json(state)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients[session_id].remove(ws)


# ── Background scan with streaming ─────────────────────────────────────────

async def _run_scan(workspace_id: str, session_id: str, targets: list[str], max_cycles: int) -> None:
    """Run the swarm and broadcast progress directly to connected WebSockets."""
    try:
        _logger.info("Scan task started", session_id=session_id, targets=targets)

        from src.agents.swarm import (
            create_initial_state, PlannerAgent, ReconAgent, AnalysisAgent,
            HypothesisAgent, RiskAgent, MemoryAgent,
        )

        state = create_initial_state(workspace_id, session_id, targets, max_cycles)

        agents_in_order = [
            ("planning",   PlannerAgent()),
            ("recon",      ReconAgent()),
            ("analysis",   AnalysisAgent()),
            ("hypothesis", HypothesisAgent()),
        ]
        post_agents = [
            ("triage",  RiskAgent()),
            ("memory",  MemoryAgent()),
        ]

        # Count total steps including testing phase
        total_steps = max_cycles * (len(agents_in_order) + 1 + len(post_agents))
        step = 0

        def _snap(phase: str, prog: float) -> dict:
            return {
                "phase": phase, "progress": prog,
                "details": {
                    "reasoning_chain": state.get("reasoning_chain", []),
                    "findings": len(state.get("findings", [])),
                    "hypotheses": len(state.get("hypotheses", [])),
                    "endpoints": len(state.get("discovered_endpoints", [])),
                    "cycle": state.get("cycle", 0) + 1,
                }
            }

        for cycle in range(max_cycles):
            # ── Recon + Analysis + Hypothesis ──────────────────────────────
            for phase, agent in agents_in_order:
                # Broadcast BEFORE so UI shows ACTIVE during execution
                await _broadcast(session_id, _snap(phase, round((step / total_steps) * 100, 1)))
                state["phase"] = phase
                state = await agent.execute(state)
                step += 1
                await _broadcast(session_id, _snap(phase, round((step / total_steps) * 100, 1)))
                await asyncio.sleep(0.2)

            # ── Testing phase: multi-vuln active probes ─────────────────────
            step += 1
            await _broadcast(session_id, _snap("testing", round((step / total_steps) * 100, 1)))
            state["phase"] = "testing"
            state["reasoning_chain"].append("[tester] Starting active vulnerability tests")

            import httpx, urllib.parse
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,*/*",
            }

            SQLI_ERRORS = [
                "you have an error in your sql syntax",
                "warning: mysql", "unclosed quotation mark",
                "quoted string not properly terminated",
                "syntax error", "odbc microsoft access driver",
                "ora-", "pg_query", "sqlite_",
            ]

            async def probe(client, url, param, payload):
                """Send a GET probe with the given payload for a param."""
                test_url = f"{url}?{urllib.parse.quote(param)}={urllib.parse.quote(payload)}"
                resp = await client.get(test_url)
                return resp, test_url

            def _already_found(title: str, url: str, param: str) -> bool:
                """Deduplicate findings — skip if same vuln+url+param already recorded."""
                return any(
                    f.get("title") == title and f.get("affected_url") == url and f.get("parameter") == param
                    for f in state.get("findings", [])
                )

            async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True, headers=headers) as client:
                for h in state.get("hypotheses", []):
                    url = h.get("url", "")
                    param = h.get("param", "")
                    cat = h.get("category", "")
                    if not url or not param:
                        continue

                    await _broadcast(session_id, _snap("testing", round((step / total_steps) * 100, 1)))

                    try:
                        # ── XSS ─────────────────────────────────────────────
                        if cat == "xss":
                            payload = "<script>alert('reconx')</script>"
                            state["reasoning_chain"].append(f"[tester] XSS probe → {url}?{param}=<script>")
                            resp, test_url = await probe(client, url, param, payload)
                            if payload in resp.text:
                                title = "Reflected Cross-Site Scripting (XSS)"
                                state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED Reflected XSS on {url} param={param}")
                                if not _already_found(title, url, param):
                                    state["findings"].append({
                                        "title": title,
                                        "affected_url": url, "parameter": param,
                                        "severity": "High", "cvss_score": 7.1,
                                        "exploitability_score": 8.0, "impact_score": 6.0,
                                        "description": f"Parameter '{param}' reflects unsanitized input.",
                                        "evidence": "Payload reflected in response body",
                                    })
                                h["confirmed"] = True
                            else:
                                state["reasoning_chain"].append(f"[tester] ❌ XSS not reflected on {url}?{param}")

                        # ── SQLi error-based ─────────────────────────────────
                        elif cat == "sqli":
                            payload = "'"
                            state["reasoning_chain"].append(f"[tester] SQLi probe → {url}?{param}='")
                            resp, test_url = await probe(client, url, param, payload)
                            body_lower = resp.text.lower()
                            matched = next((e for e in SQLI_ERRORS if e in body_lower), None)
                            if matched:
                                title = "SQL Injection"
                                state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED SQLi on {url} param={param} — error: {matched}")
                                if not _already_found(title, url, param):
                                    state["findings"].append({
                                        "title": title,
                                        "affected_url": url, "parameter": param,
                                        "severity": "Critical", "cvss_score": 9.8,
                                        "exploitability_score": 9.0, "impact_score": 9.0,
                                        "description": f"Parameter '{param}' is injectable — SQL error detected: '{matched}'",
                                        "evidence": matched,
                                    })
                                h["confirmed"] = True
                            else:
                                # Try boolean-based: original vs modified response size check
                                resp_true, _ = await probe(client, url, param, "1 OR 1=1")
                                resp_false, _ = await probe(client, url, param, "1 AND 1=2")
                                if abs(len(resp_true.text) - len(resp_false.text)) > 50:
                                    title = "Blind SQL Injection (Boolean-Based)"
                                    state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED Blind SQLi on {url} param={param} (boolean-based)")
                                    if not _already_found(title, url, param):
                                        state["findings"].append({
                                            "title": title,
                                            "affected_url": url, "parameter": param,
                                            "severity": "Critical", "cvss_score": 9.1,
                                            "exploitability_score": 8.5, "impact_score": 9.0,
                                            "description": f"Parameter '{param}' shows different responses for TRUE/FALSE conditions.",
                                            "evidence": f"Response size diff: {abs(len(resp_true.text) - len(resp_false.text))} bytes",
                                        })
                                    h["confirmed"] = True
                                else:
                                    state["reasoning_chain"].append(f"[tester] ❌ No SQLi detected on {url}?{param}")

                        # ── LFI / Path Traversal ─────────────────────────────
                        if "page" in param.lower() or "file" in param.lower() or "path" in param.lower() or "include" in param.lower():
                            lfi_payload = "../../../etc/passwd"
                            state["reasoning_chain"].append(f"[tester] LFI probe → {url}?{param}=../../../etc/passwd")
                            resp, _ = await probe(client, url, param, lfi_payload)
                            if "root:" in resp.text or "bin/bash" in resp.text or "etc/passwd" in resp.text:
                                title = "Local File Inclusion (LFI)"
                                state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED LFI on {url} param={param}")
                                if not _already_found(title, url, param):
                                    state["findings"].append({
                                        "title": title,
                                        "affected_url": url, "parameter": param,
                                        "severity": "Critical", "cvss_score": 9.3,
                                        "exploitability_score": 9.0, "impact_score": 9.5,
                                        "description": f"Parameter '{param}' includes local files — /etc/passwd disclosed.",
                                        "evidence": "root: found in response",
                                    })
                            else:
                                state["reasoning_chain"].append(f"[tester] ❌ LFI not confirmed on {url}?{param}")

                    except Exception as ex:
                        state["reasoning_chain"].append(f"[tester] Probe error on {url}?{param}: {type(ex).__name__}")
                    await asyncio.sleep(0.15)

            state["reasoning_chain"].append(f"[tester] Testing complete — {len(state.get('findings', []))} findings confirmed")
            await _broadcast(session_id, _snap("testing", round((step / total_steps) * 100, 1)))
            await asyncio.sleep(0.2)


            # ── Triage + Memory ─────────────────────────────────────────────
            for phase, agent in post_agents:
                await _broadcast(session_id, _snap(phase, round((step / total_steps) * 100, 1)))
                state["phase"] = phase
                state = await agent.execute(state)
                step += 1
                await _broadcast(session_id, _snap(phase, round((step / total_steps) * 100, 1)))
                await asyncio.sleep(0.2)


        # Final complete broadcast
        final = {
            "phase": "complete",
            "progress": 100.0,
            "details": {
                "reasoning_chain": state.get("reasoning_chain", []),
                "findings": len(state.get("findings", [])),
                "hypotheses": len(state.get("hypotheses", [])),
                "endpoints": len(state.get("discovered_endpoints", [])),
                "cycle": max_cycles,
            }
        }
        await _broadcast(session_id, final)
        _logger.info("Scan complete", session_id=session_id,
                     findings=len(state.get("findings", [])),
                     endpoints=len(state.get("discovered_endpoints", [])))

    except Exception as exc:
        _logger.error("Scan task FAILED", session_id=session_id, error=str(exc), exc_info=True)
        await _broadcast(session_id, {
            "phase": "error",
            "progress": 0,
            "details": {
                "reasoning_chain": [f"[error] Scan failed: {exc}"],
                "findings": 0, "hypotheses": 0, "endpoints": 0, "cycle": 0
            }
        })


# ── REST endpoint: start session ────────────────────────────────────────────

@router.post("/session/start")
async def start_session(request: SessionRequest):
    """Start an autonomous agent swarm session."""
    session_id = str(uuid.uuid4())
    _sessions[session_id] = {
        "phase": "initializing", "progress": 0,
        "details": {
            "reasoning_chain": ["[system] Autonomous engine received request. Launching agents..."],
            "findings": 0, "hypotheses": 0, "endpoints": 0, "cycle": 0,
        }
    }
    _ws_clients[session_id] = []
    asyncio.create_task(_run_scan(request.workspace_id, session_id, request.targets, request.max_cycles))
    return {"session_id": session_id, "phase": "initializing"}


# ── REST endpoint: poll progress ────────────────────────────────────────────

@router.get("/session/{session_id}/progress")
async def get_session_progress(session_id: str):
    """REST polling endpoint — returns latest scan state."""
    return _sessions.get(session_id, {
        "phase": "not_found", "progress": 0,
        "details": {"reasoning_chain": [], "findings": 0, "hypotheses": 0, "endpoints": 0}
    })


# ── WebSocket: live streaming ───────────────────────────────────────────────

@router.websocket("/ws/{session_id}")
async def session_ws(websocket: WebSocket, session_id: str):
    """Direct WebSocket — streams scan progress without Redis middleware."""
    await websocket.accept()
    if session_id not in _ws_clients:
        _ws_clients[session_id] = []
    _ws_clients[session_id].append(websocket)

    # Send current state immediately on connect
    if session_id in _sessions:
        await websocket.send_json(_sessions[session_id])

    try:
        while True:
            await asyncio.sleep(1)
            # Keep alive ping
            current = _sessions.get(session_id, {})
            if current.get("phase") in ("complete", "error", "not_found"):
                break
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        if session_id in _ws_clients and websocket in _ws_clients[session_id]:
            _ws_clients[session_id].remove(websocket)
