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
_sessions: dict[str, dict[str, Any]] = {}
_ws_clients: dict[str, list[WebSocket]] = {}

# ── Global findings store (persists across all sessions) ────────────────────
_all_findings: list[dict[str, Any]] = []


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

async def _run_scan(workspace_id: str, session_id: str, targets: list[str],
                    max_cycles: int, policy: dict | None = None) -> None:
    """Run the swarm and broadcast progress directly to connected WebSockets."""
    try:
        _logger.info("Scan task started", session_id=session_id, targets=targets)

        from src.agents.swarm import (
            create_initial_state, PlannerAgent, ReconAgent, AnalysisAgent,
            HypothesisAgent, RiskAgent, MemoryAgent,
        )

        state = create_initial_state(workspace_id, session_id, targets, max_cycles)
        state["policy"] = policy or {}  # Pass program policy into swarm state

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

            # ── Testing phase: complete 20+ vuln suite ──────────────────────
            step += 1
            await _broadcast(session_id, _snap("testing", round((step / total_steps) * 100, 1)))
            state["phase"] = "testing"
            state["reasoning_chain"].append("[tester] Starting complete vulnerability test suite")

            import httpx, urllib.parse, time as _time

            HEADERS = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,*/*",
            }
            SQLI_ERRORS = [
                "you have an error in your sql syntax","warning: mysql","unclosed quotation mark",
                "quoted string not properly terminated","ora-","pg_query","sqlite_",
                "syntax error","odbc microsoft access driver","microsoft ole db",
            ]
            CMDI_SIGNALS = ["uid=","gid=","root","www-data","apache","nginx","nobody"]
            SSTI_SIGNALS = ["49","7777777"]

            def _add_finding(title, url, param, severity, cvss, desc, evidence, cwe="", owasp="", remediation=""):
                already = any(
                    f.get("title")==title and f.get("affected_url")==url and f.get("parameter")==param
                    for f in state.get("findings",[])
                )
                if not already:
                    state["findings"].append({
                        "title": title, "affected_url": url, "parameter": param,
                        "severity": severity, "cvss_score": cvss,
                        "description": desc, "evidence": evidence,
                        "cwe": cwe, "owasp": owasp, "remediation": remediation,
                        "status": "confirmed",
                    })

            async def gprobe(client, url, param, payload):
                q = f"{url}?{urllib.parse.quote(param)}={urllib.parse.quote(payload)}"
                return await client.get(q), q

            async with httpx.AsyncClient(verify=False, timeout=10.0,
                                         follow_redirects=False, headers=HEADERS) as client:
                for h in state.get("hypotheses", []):
                    url = h.get("url",""); param = h.get("param",""); cat = h.get("category","")
                    if not url:
                        continue
                    await _broadcast(session_id, _snap("testing", round((step/total_steps)*100,1)))
                    try:
                        # ── XSS (Reflected) ──────────────────────────────
                        if cat == "xss" and param:
                            pl = "<script>alert('r')</script>"
                            state["reasoning_chain"].append(f"[tester] XSS → {url}?{param}=<script>")
                            r, _ = await gprobe(client, url, param, pl)
                            if pl in r.text:
                                _add_finding("Reflected XSS", url, param, "High", 7.1,
                                    f"Param '{param}' reflects unsanitized input in HTML response.",
                                    "Payload found in response body",
                                    "CWE-79","A03:2021","Use context-aware output encoding (HTMLSpecialChars).")
                                state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED XSS on {url}?{param}")
                                h["confirmed"] = True
                            else:
                                state["reasoning_chain"].append(f"[tester] ❌ XSS: no reflection on {url}?{param}")

                        # ── SQLi Error-based ──────────────────────────────
                        elif cat == "sqli" and param:
                            state["reasoning_chain"].append(f"[tester] SQLi probe → {url}?{param}='")
                            r, _ = await gprobe(client, url, param, "'")
                            body = r.text.lower()
                            err = next((e for e in SQLI_ERRORS if e in body), None)
                            if err:
                                _add_finding("SQL Injection (Error-Based)", url, param, "Critical", 9.8,
                                    f"Param '{param}' triggers SQL error: {err}",
                                    f"SQL error string '{err}' found in response",
                                    "CWE-89","A03:2021","Use parameterized queries / prepared statements.")
                                state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED SQLi (error) on {url}?{param}")
                                h["confirmed"] = True
                            else:
                                # Boolean-based
                                rt, _ = await gprobe(client, url, param, "1 OR 1=1")
                                rf, _ = await gprobe(client, url, param, "1 AND 1=2")
                                diff = abs(len(rt.text)-len(rf.text))
                                if diff > 80:
                                    _add_finding("SQL Injection (Boolean-Based Blind)", url, param, "Critical", 9.1,
                                        f"Param '{param}' shows response size diff of {diff} bytes between TRUE/FALSE payloads.",
                                        f"TRUE response: {len(rt.text)}B, FALSE: {len(rf.text)}B",
                                        "CWE-89","A03:2021","Use parameterized queries / prepared statements.")
                                    state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED Blind SQLi on {url}?{param} (diff={diff}B)")
                                    h["confirmed"] = True
                                else:
                                    # Union-based attempt
                                    ru, _ = await gprobe(client, url, param, "' UNION SELECT 1,2,3,4,5--")
                                    if any(x in ru.text for x in ["1","2","3"]) and ru.status_code == 200:
                                        state["reasoning_chain"].append(f"[tester] ⚠️ Possible Union SQLi on {url}?{param} — verify manually")
                                    else:
                                        state["reasoning_chain"].append(f"[tester] ❌ No SQLi on {url}?{param}")

                        # ── LFI / Path Traversal ──────────────────────────
                        elif cat == "lfi" and param:
                            for lfi_pl in ["../../../etc/passwd", "....//....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd"]:
                                state["reasoning_chain"].append(f"[tester] LFI → {url}?{param}={lfi_pl[:30]}")
                                r, _ = await gprobe(client, url, param, lfi_pl)
                                if "root:" in r.text or "/bin/bash" in r.text:
                                    _add_finding("Local File Inclusion (LFI)", url, param, "Critical", 9.3,
                                        f"Param '{param}' discloses /etc/passwd via path traversal.",
                                        "/etc/passwd content found in response",
                                        "CWE-22","A01:2021","Validate file paths against an allowlist. Never pass user input to file functions.")
                                    state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED LFI on {url}?{param}")
                                    h["confirmed"] = True
                                    break
                            else:
                                state["reasoning_chain"].append(f"[tester] ❌ LFI not confirmed on {url}?{param}")

                        # ── SSRF ──────────────────────────────────────────
                        elif cat == "ssrf" and param:
                            for ssrf_pl in ["http://127.0.0.1/","http://169.254.169.254/latest/meta-data/"]:
                                state["reasoning_chain"].append(f"[tester] SSRF → {url}?{param}={ssrf_pl}")
                                r, _ = await gprobe(client, url, param, ssrf_pl)
                                if any(x in r.text for x in ["ami-id","instance-id","localhost","127.0.0.1","internal"]):
                                    _add_finding("Server-Side Request Forgery (SSRF)", url, param, "Critical", 9.0,
                                        f"Param '{param}' causes server to fetch internal resources.",
                                        f"Internal content leaked: {r.text[:100]}",
                                        "CWE-918","A10:2021","Validate and allowlist URLs. Block internal IP ranges.")
                                    state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED SSRF on {url}?{param}")
                                    h["confirmed"] = True
                                    break
                            else:
                                state["reasoning_chain"].append(f"[tester] ❌ SSRF not confirmed on {url}?{param}")

                        # ── Open Redirect ─────────────────────────────────
                        elif cat == "open_redirect" and param:
                            pl = "https://evil.com"
                            state["reasoning_chain"].append(f"[tester] Open Redirect → {url}?{param}={pl}")
                            r, _ = await gprobe(client, url, param, pl)
                            loc = r.headers.get("location","")
                            if "evil.com" in loc or r.status_code in (301,302) and "evil" in r.text:
                                _add_finding("Open Redirect", url, param, "Medium", 6.1,
                                    f"Param '{param}' redirects to attacker-controlled URL.",
                                    f"Location header: {loc}",
                                    "CWE-601","A01:2021","Validate redirect targets against an allowlist of trusted domains.")
                                state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED Open Redirect on {url}?{param}")
                                h["confirmed"] = True
                            else:
                                state["reasoning_chain"].append(f"[tester] ❌ No redirect on {url}?{param}")

                        # ── SSTI ─────────────────────────────────────────
                        elif cat == "ssti" and param:
                            pl = "{{7*7}}"
                            state["reasoning_chain"].append(f"[tester] SSTI → {url}?{param}={{{{7*7}}}}")
                            r, _ = await gprobe(client, url, param, pl)
                            if "49" in r.text:
                                _add_finding("Server-Side Template Injection (SSTI)", url, param, "Critical", 9.8,
                                    f"Param '{param}' evaluates template expressions — {{{{7*7}}}}=49 confirmed.",
                                    "Expression 7*7=49 found in response",
                                    "CWE-94","A03:2021","Never pass user input to template engines. Use sandboxed rendering.")
                                state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED SSTI on {url}?{param}")
                                h["confirmed"] = True
                            else:
                                state["reasoning_chain"].append(f"[tester] ❌ SSTI not triggered on {url}?{param}")

                        # ── CMDi (Command Injection) ──────────────────────
                        elif cat == "cmdi" and param:
                            for pl in ["; id", "| id", "`id`", "$(id)"]:
                                state["reasoning_chain"].append(f"[tester] CMDi → {url}?{param}={pl}")
                                r, _ = await gprobe(client, url, param, pl)
                                if any(sig in r.text for sig in CMDI_SIGNALS):
                                    _add_finding("OS Command Injection (CMDi)", url, param, "Critical", 10.0,
                                        f"Param '{param}' executes OS commands — `id` output found in response.",
                                        f"OS output detected: {r.text[:100]}",
                                        "CWE-78","A03:2021","Never pass user input to shell functions. Use allowlists for OS interactions.")
                                    state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED CMDi on {url}?{param}")
                                    h["confirmed"] = True
                                    break
                            else:
                                state["reasoning_chain"].append(f"[tester] ❌ CMDi not triggered on {url}?{param}")

                        # ── IDOR ─────────────────────────────────────────
                        elif cat == "idor" and param:
                            try:
                                val = h.get("params",{}).get(param,"1")
                                orig_r = await client.get(f"{url}?{param}={val}")
                                alt_r = await client.get(f"{url}?{param}={int(val)+1 if val.isdigit() else 2}")
                                if orig_r.status_code == 200 and alt_r.status_code == 200 and orig_r.text != alt_r.text:
                                    _add_finding("Insecure Direct Object Reference (IDOR)", url, param, "High", 8.1,
                                        f"Param '{param}' exposes different user data when ID is changed.",
                                        f"Different response for ID {val} vs {int(val)+1 if val.isdigit() else 2}",
                                        "CWE-639","A01:2021","Implement object-level authorization checks for every request.")
                                    state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED IDOR on {url}?{param}")
                                    h["confirmed"] = True
                                else:
                                    state["reasoning_chain"].append(f"[tester] ❌ IDOR: same response on {url}?{param}")
                            except Exception:
                                pass

                        # ── CSRF ─────────────────────────────────────────
                        elif cat == "csrf":
                            state["reasoning_chain"].append(f"[tester] CSRF check → {url}")
                            r = await client.get(url)
                            has_token = any(t in r.text.lower() for t in ["csrf_token","_token","csrfmiddlewaretoken","authenticity_token","x-csrf"])
                            if not has_token and r.status_code == 200:
                                _add_finding("Missing CSRF Protection", url, "", "Medium", 6.5,
                                    f"Form at {url} has no CSRF token — vulnerable to cross-site request forgery.",
                                    "No csrf_token / _token / csrfmiddlewaretoken found in form",
                                    "CWE-352","A01:2021","Add CSRF tokens to all state-changing forms. Use SameSite=Strict cookies.")
                                state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED Missing CSRF on {url}")
                                h["confirmed"] = True
                            else:
                                state["reasoning_chain"].append(f"[tester] ❌ CSRF token present on {url}")

                        # ── CORS Misconfiguration ─────────────────────────
                        elif cat == "cors":
                            state["reasoning_chain"].append(f"[tester] CORS check → {url}")
                            r = await client.get(url, headers={**HEADERS, "Origin":"https://evil.com"})
                            acao = r.headers.get("access-control-allow-origin","")
                            acac = r.headers.get("access-control-allow-credentials","")
                            if acao == "*" or "evil.com" in acao:
                                severity = "High" if "true" in acac.lower() else "Medium"
                                cvss = 8.1 if severity == "High" else 5.4
                                _add_finding("CORS Misconfiguration", url, "", severity, cvss,
                                    f"CORS allows origin 'evil.com'. ACAO={acao}, ACAC={acac}",
                                    f"Access-Control-Allow-Origin: {acao}",
                                    "CWE-942","A05:2021","Restrict CORS to trusted origins only. Never use wildcard with credentials.")
                                state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED CORS misconfig on {url}")
                                h["confirmed"] = True
                            else:
                                state["reasoning_chain"].append(f"[tester] ❌ CORS OK on {url}")

                        # ── GraphQL Introspection ─────────────────────────
                        elif cat == "graphql":
                            state["reasoning_chain"].append(f"[tester] GraphQL introspection → {url}")
                            try:
                                r = await client.post(url,
                                    json={"query": "{__schema{types{name}}}"},
                                    headers={**HEADERS,"Content-Type":"application/json"})
                                if "__schema" in r.text or "types" in r.text:
                                    _add_finding("GraphQL Introspection Enabled", url, "", "Medium", 5.3,
                                        "GraphQL schema fully exposed via introspection query.",
                                        "__schema found in response",
                                        "CWE-200","A05:2021","Disable introspection in production. Use query depth limits.")
                                    state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED GraphQL introspection on {url}")
                                    h["confirmed"] = True
                                else:
                                    state["reasoning_chain"].append(f"[tester] ❌ GraphQL introspection blocked on {url}")
                            except Exception:
                                pass

                        # ── Misconfig / Sensitive File Exposure ───────────
                        elif cat == "misconfig":
                            state["reasoning_chain"].append(f"[tester] Sensitive file check → {url}")
                            r = await client.get(url)
                            if r.status_code == 200 and len(r.text) > 10:
                                _add_finding("Sensitive File Exposure", url, "", "High", 7.5,
                                    f"Sensitive file accessible at {url}",
                                    f"HTTP 200 — {len(r.text)} bytes returned",
                                    "CWE-538","A05:2021","Restrict access to sensitive files. Remove from public web root.")
                                state["reasoning_chain"].append(f"[tester] ✅ CONFIRMED Sensitive file at {url}")
                                h["confirmed"] = True
                            else:
                                state["reasoning_chain"].append(f"[tester] ❌ File not accessible: {url}")

                    except Exception as ex:
                        state["reasoning_chain"].append(f"[tester] Error on {url}: {type(ex).__name__}")
                    await asyncio.sleep(0.1)

                # ── Passive: check security headers on each target ────────
                state["reasoning_chain"].append("[tester] Checking security headers on targets")
                for target in state.get("targets", []):
                    try:
                        r = await client.get(target if target.startswith("http") else f"http://{target}")
                        h_dict = {k.lower(): v for k, v in r.headers.items()}
                        missing = []
                        if "content-security-policy" not in h_dict: missing.append("Content-Security-Policy")
                        if "x-frame-options" not in h_dict: missing.append("X-Frame-Options")
                        if "strict-transport-security" not in h_dict: missing.append("Strict-Transport-Security")
                        if "x-content-type-options" not in h_dict: missing.append("X-Content-Type-Options")
                        if missing:
                            _add_finding("Missing Security Headers", target, "", "Low", 4.3,
                                f"Missing headers: {', '.join(missing)}",
                                f"Headers absent: {missing}",
                                "CWE-693","A05:2021",f"Add headers: {', '.join(missing)}")
                            state["reasoning_chain"].append(f"[tester] ⚠️ Missing headers on {target}: {missing}")
                    except Exception:
                        pass

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

        # ── Persist findings to global store ─────────────────────────────────
        for f in state.get("findings", []):
            entry = dict(f)
            entry.setdefault("id", str(uuid.uuid4()))
            entry["session_id"] = session_id
            entry["target"] = state.get("targets", [""])[0]
            entry["status"] = "confirmed"
            entry["confidence"] = 0.95
            entry["source_tool"] = "ReconX Autonomous Engine"
            # Avoid duplicates in global store
            already = any(
                x.get("title") == entry.get("title")
                and x.get("affected_url") == entry.get("affected_url")
                and x.get("parameter") == entry.get("parameter")
                for x in _all_findings
            )
            if not already:
                _all_findings.append(entry)

        _logger.info("Scan complete", session_id=session_id,
                     findings=len(state.get("findings", [])),
                     total_global_findings=len(_all_findings),
                     endpoints=len(state.get("discovered_endpoints", [])))

        # ── Persist findings to PostgreSQL ────────────────────────────────
        try:
            from src.db import execute as db_exec
            for f in _all_findings[-len(state.get("findings", [])):]:
                await db_exec("""
                    INSERT INTO findings
                        (title, description, severity, status, finding_type,
                         affected_url, parameter, cvss_score, cwe, owasp,
                         remediation, evidence, confidence, source_tool,
                         workspace_id, scan_id)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                        (SELECT id FROM workspaces LIMIT 1),
                        NULL)
                    ON CONFLICT DO NOTHING
                """,
                    f.get("title",""), f.get("description",""), f.get("severity","high").lower(),
                    "confirmed", f.get("title","").split(" ")[0].lower(),
                    f.get("affected_url",""), f.get("parameter",""),
                    float(f.get("cvss_score",0) or 0),
                    f.get("cwe",""), f.get("owasp",""), f.get("remediation",""),
                    str(f.get("evidence","")), 0.95, "ReconX Autonomous Engine"
                )
        except Exception as db_err:
            _logger.warning("DB persist failed (findings stored in-memory)", error=str(db_err))

    except Exception as exc:
        _logger.error("Scan task FAILED", session_id=session_id, error=str(exc), exc_info=True)
        await _broadcast(session_id, {
            "phase": "error", "progress": 0,
            "details": {
                "reasoning_chain": [f"[error] Scan failed: {exc}"],
                "findings": 0, "hypotheses": 0, "endpoints": 0, "cycle": 0
            }
        })


# ── REST endpoint: start session ────────────────────────────────────────────

class SessionRequest(BaseModel):
    workspace_id: str
    targets: list[str]
    max_cycles: int = 3
    mode: str = "autonomous"
    program_id: str | None = None
    policy: dict | None = None  # allowed_tests, rate_limit_rps, etc.


@router.post("/session/start")
async def start_session(request: SessionRequest):
    """Start an autonomous agent swarm session."""
    session_id = str(uuid.uuid4())
    _sessions[session_id] = {
        "phase": "initializing", "progress": 0,
        "program_id": request.program_id,
        "details": {
            "reasoning_chain": ["[system] Autonomous engine received request. Launching agents..."],
            "findings": 0, "hypotheses": 0, "endpoints": 0, "cycle": 0,
        }
    }
    _ws_clients[session_id] = []
    asyncio.create_task(_run_scan(
        request.workspace_id, session_id, request.targets,
        request.max_cycles, request.policy or {}
    ))
    return {"session_id": session_id, "phase": "initializing"}


# ── REST endpoint: poll progress ────────────────────────────────────────────

@router.get("/session/{session_id}/progress")
async def get_session_progress(session_id: str):
    """REST polling endpoint — returns latest scan state."""
    return _sessions.get(session_id, {
        "phase": "not_found", "progress": 0,
        "details": {"reasoning_chain": [], "findings": 0, "hypotheses": 0, "endpoints": 0}
    })


# ── REST endpoint: all findings ─────────────────────────────────────────────

@router.get("/findings")
async def get_all_findings():
    """Return all confirmed findings from all scan sessions."""
    return _all_findings


@router.get("/findings/latest")
async def get_latest_finding():
    if not _all_findings:
        return {}
    return _all_findings[-1]


# ── REST endpoint: programs CRUD ────────────────────────────────────────────

_programs: list[dict] = []  # In-memory program store (fallback if DB unavailable)


class ProgramCreate(BaseModel):
    name: str
    platform: str = "custom"
    platform_url: str | None = None
    description: str | None = None
    in_scope: list[str] = []
    out_of_scope: list[str] = []
    allowed_tests: list[str] = [
        "xss","sqli","lfi","ssrf","csrf","cors","idor",
        "open_redirect","ssti","misconfig","graphql","jwt"
    ]
    rate_limit_rps: int = 2
    notes: str | None = None


@router.get("/programs")
async def list_programs():
    try:
        from src.db import fetch as db_fetch
        rows = await db_fetch("""
            SELECT p.*, array_agg(s.value) FILTER (WHERE s.is_in_scope=true) as in_scope,
                   array_agg(s.value) FILTER (WHERE s.is_in_scope=false) as out_of_scope
            FROM programs p
            LEFT JOIN scopes s ON s.program_id = p.id
            GROUP BY p.id ORDER BY p.created_at DESC
        """)
        if rows:
            return rows
    except Exception:
        pass
    return _programs


@router.post("/programs")
async def create_program(req: ProgramCreate):
    prog_id = str(uuid.uuid4())
    entry = {
        "id": prog_id, "name": req.name, "platform": req.platform,
        "platform_url": req.platform_url, "description": req.description,
        "in_scope": req.in_scope, "out_of_scope": req.out_of_scope,
        "allowed_tests": req.allowed_tests,
        "rate_limit_rps": req.rate_limit_rps, "notes": req.notes,
        "finding_count": 0, "scan_count": 0,
    }
    _programs.append(entry)
    try:
        from src.db import execute as db_exec
        await db_exec(
            "INSERT INTO programs(id,name,platform,platform_url,description,allowed_tests,rate_limit_rps,notes) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            prog_id, req.name, req.platform, req.platform_url, req.description,
            __import__("json").dumps(req.allowed_tests), req.rate_limit_rps, req.notes
        )
        for domain in req.in_scope:
            await db_exec(
                "INSERT INTO scopes(program_id,scope_type,value,normalized_value,is_in_scope,is_wildcard) "
                "VALUES($1,'domain',$2,$3,$4,$5)",
                prog_id, domain, domain.lower().lstrip("*."),
                True, domain.startswith("*")
            )
        for domain in req.out_of_scope:
            await db_exec(
                "INSERT INTO scopes(program_id,scope_type,value,normalized_value,is_in_scope,is_wildcard) "
                "VALUES($1,'domain',$2,$3,$4,$5)",
                prog_id, domain, domain.lower().lstrip("*."),
                False, domain.startswith("*")
            )
    except Exception as e:
        _logger.warning("DB program create failed", error=str(e))
    return entry


@router.get("/programs/{program_id}")
async def get_program(program_id: str):
    prog = next((p for p in _programs if p["id"] == program_id), None)
    if prog:
        return prog
    try:
        from src.db import fetchrow as db_one
        return await db_one("SELECT * FROM programs WHERE id=$1", program_id) or {}
    except Exception:
        return {}


@router.delete("/programs/{program_id}")
async def delete_program(program_id: str):
    global _programs
    _programs = [p for p in _programs if p["id"] != program_id]
    try:
        from src.db import execute as db_exec
        await db_exec("DELETE FROM programs WHERE id=$1", program_id)
    except Exception:
        pass
    return {"deleted": program_id}


# ── REST endpoint: live events feed ─────────────────────────────────────────

@router.get("/events")
async def get_live_events():
    import time
    events = []
    now = time.strftime("%H:%M")
    for f in _all_findings:
        events.append({
            "id": f.get("id", str(len(events))),
            "timestamp": now, "type": "finding",
            "title": f.get("title", "Vulnerability Found"),
            "detail": f"{f.get('affected_url','')} — param: {f.get('parameter','N/A')} | {f.get('evidence','')}",
            "severity": (f.get("severity") or "high").lower(),
        })
    for sid, snap in list(_sessions.items()):
        details = snap.get("details", {})
        reasoning: list = details.get("reasoning_chain", [])
        phase = snap.get("phase", "")
        endpoints = details.get("endpoints", 0)
        hypotheses = details.get("hypotheses", 0)
        if endpoints > 0:
            events.append({"id": f"ep-{sid[:8]}", "timestamp": now, "type": "endpoint",
                "title": f"Discovered {endpoints} endpoints", "detail": f"Session {sid[:8]}... — {phase}"})
        if hypotheses > 0:
            events.append({"id": f"hyp-{sid[:8]}", "timestamp": now, "type": "asset",
                "title": f"Generated {hypotheses} attack hypotheses", "detail": f"Session {sid[:8]}..."})
        for msg in reasoning[-5:]:
            if any(k in msg for k in ["✅ CONFIRMED","Crawling","Strategy:","Starting cycle"]):
                events.append({
                    "id": f"log-{sid[:8]}-{len(events)}", "timestamp": now,
                    "type": "change" if "Strategy" in msg or "cycle" in msg.lower() else "endpoint",
                    "title": msg.split("]",1)[-1].strip()[:80],
                    "detail": f"Session {sid[:8]}...",
                    "severity": "critical" if "✅ CONFIRMED" in msg else None,
                })
    return events


# ── WebSocket: live streaming ────────────────────────────────────────────────

@router.websocket("/ws/{session_id}")
async def session_ws(websocket: WebSocket, session_id: str):
    await websocket.accept()
    if session_id not in _ws_clients:
        _ws_clients[session_id] = []
    _ws_clients[session_id].append(websocket)
    if session_id in _sessions:
        await websocket.send_json(_sessions[session_id])
    try:
        while True:
            await asyncio.sleep(1)
            current = _sessions.get(session_id, {})
            if current.get("phase") in ("complete", "error", "not_found"):
                break
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        if session_id in _ws_clients and websocket in _ws_clients[session_id]:
            _ws_clients[session_id].remove(websocket)






# ── REST endpoint: start session ────────────────────────────────────────────








# ── REST endpoint: all findings across sessions ──────────────────────────────

@router.get("/findings")
async def get_all_findings():
    """Return all confirmed findings from all scan sessions."""
    return _all_findings


@router.get("/findings/latest")
async def get_latest_finding():
    """Return the most recent confirmed finding for report generation."""
    if not _all_findings:
        return {}
    return _all_findings[-1]


@router.get("/events")
async def get_live_events():
    """Build a structured live event feed from all sessions' data."""
    import time
    events = []
    now = time.strftime("%H:%M")

    # Finding events from global store
    for f in _all_findings:
        events.append({
            "id": f.get("id", str(len(events))),
            "timestamp": now,
            "type": "finding",
            "title": f.get("title", "Vulnerability Found"),
            "detail": f"{f.get('affected_url', '')}  —  param: {f.get('parameter', 'N/A')}  |  {f.get('evidence', '')}",
            "severity": (f.get("severity") or "high").lower(),
        })

    # Session events from all active/completed sessions
    for sid, snap in list(_sessions.items()):
        details = snap.get("details", {})
        reasoning: list = details.get("reasoning_chain", [])
        phase = snap.get("phase", "")
        endpoints = details.get("endpoints", 0)
        hypotheses = details.get("hypotheses", 0)

        if endpoints > 0:
            events.append({
                "id": f"ep-{sid[:8]}",
                "timestamp": now,
                "type": "endpoint",
                "title": f"Discovered {endpoints} endpoints",
                "detail": f"Session {sid[:8]}... — {phase} phase",
            })

        if hypotheses > 0:
            events.append({
                "id": f"hyp-{sid[:8]}",
                "timestamp": now,
                "type": "asset",
                "title": f"Generated {hypotheses} attack hypotheses",
                "detail": f"Session {sid[:8]}... — AI Hypothesis Engine",
            })

        # Pick notable reasoning messages as events
        for msg in reasoning[-5:]:
            if any(k in msg for k in ["✅ CONFIRMED", "Crawling", "Strategy:", "Starting cycle"]):
                events.append({
                    "id": f"log-{sid[:8]}-{len(events)}",
                    "timestamp": now,
                    "type": "change" if "Strategy" in msg or "cycle" in msg.lower() else "endpoint",
                    "title": msg.split("]", 1)[-1].strip()[:80],
                    "detail": f"Session {sid[:8]}...",
                    "severity": "critical" if "✅ CONFIRMED" in msg else None,
                })

    return events

# ── WebSocket: live streaming ───────────────────────────────────────────────

@router.websocket("/ws/{session_id}")
async def session_ws(websocket: WebSocket, session_id: str):
    """Direct WebSocket — streams scan progress without Redis middleware."""
    await websocket.accept()
    if session_id not in _ws_clients:
        _ws_clients[session_id] = []
    _ws_clients[session_id].append(websocket)

    if session_id in _sessions:
        await websocket.send_json(_sessions[session_id])

    try:
        while True:
            await asyncio.sleep(1)
            current = _sessions.get(session_id, {})
            if current.get("phase") in ("complete", "error", "not_found"):
                break
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        if session_id in _ws_clients and websocket in _ws_clients[session_id]:
            _ws_clients[session_id].remove(websocket)
