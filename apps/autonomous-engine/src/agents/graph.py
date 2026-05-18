"""LangGraph Workflow Compiler — builds the autonomous agent state machine.

Compiles agents into a cyclic graph:
  Plan → Recon → Analyze → Hypothesize → Test → Triage → Report → Memory → (loop)
"""

from __future__ import annotations
from typing import Any
import structlog

logger = structlog.get_logger(__name__)

try:
    from langgraph.graph import StateGraph, END

    from src.agents.swarm import (
        SwarmState, SwarmPhase, create_initial_state,
        PlannerAgent, ReconAgent, AnalysisAgent, HypothesisAgent,
        RiskAgent, MemoryAgent, SafetyGuardrails,
    )

    def build_swarm_graph() -> Any:
        """Build the LangGraph state machine for the agent swarm."""

        planner = PlannerAgent()
        recon = ReconAgent()
        analysis = AnalysisAgent()
        hypothesis = HypothesisAgent()
        risk = RiskAgent()
        memory = MemoryAgent()

        async def plan_node(state: SwarmState) -> SwarmState:
            return await planner.execute(state)

        async def recon_node(state: SwarmState) -> SwarmState:
            return await recon.execute(state)

        async def analyze_node(state: SwarmState) -> SwarmState:
            return await analysis.execute(state)

        async def hypothesis_node(state: SwarmState) -> SwarmState:
            return await hypothesis.execute(state)

        async def test_node(state: SwarmState) -> SwarmState:
            state["phase"] = SwarmPhase.TESTING
            state["reasoning_chain"].append("[testing] Executing active payloads against hypotheses")
            
            import httpx
            import urllib.parse
            
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                for h in state.get("hypotheses", []):
                    url = h.get("url")
                    param = h.get("param")
                    cat = h.get("category")
                    
                    if not url or not param:
                        continue
                        
                    if cat == "xss":
                        state["reasoning_chain"].append(f"[testing] Sending XSS payload to {url}?{param}=...")
                        try:
                            payload = "<script>alert('reconx')</script>"
                            test_url = f"{url}?{urllib.parse.quote(param)}={urllib.parse.quote(payload)}"
                            resp = await client.get(test_url)
                            if payload in resp.text:
                                state["reasoning_chain"].append(f"[testing] [VULN] XSS confirmed on {url}")
                                h["confirmed"] = True
                                state["findings"].append({
                                    "title": f"Reflected Cross-Site Scripting (XSS)",
                                    "affected_url": url,
                                    "severity": "High",
                                    "cvss_score": 7.1,
                                    "exploitability_score": 8.0,
                                    "impact_score": 6.0,
                                    "description": f"The parameter '{param}' reflects input without sanitization.",
                                    "raw_request": f"GET {test_url}",
                                })
                        except Exception as e:
                            pass
                            
            return state

        async def triage_node(state: SwarmState) -> SwarmState:
            state["phase"] = SwarmPhase.TRIAGE
            state["reasoning_chain"].append("[triage] Running AI triage pipeline")
            state["triaged_findings"] = state.get("findings", [])
            return await risk.execute(state)

        async def report_node(state: SwarmState) -> SwarmState:
            state["phase"] = SwarmPhase.REPORTING
            state["reasoning_chain"].append("[reporting] Generating reports")
            return state

        async def memory_node(state: SwarmState) -> SwarmState:
            return await memory.execute(state)

        def should_continue(state: SwarmState) -> str:
            if state.get("phase") == SwarmPhase.COMPLETE:
                return "end"
            if state.get("guardrail_violations"):
                return "end"
            return "plan"

        # Build graph
        graph = StateGraph(SwarmState)

        graph.add_node("plan", plan_node)
        graph.add_node("recon", recon_node)
        graph.add_node("analyze", analyze_node)
        graph.add_node("hypothesize", hypothesis_node)
        graph.add_node("test", test_node)
        graph.add_node("triage", triage_node)
        graph.add_node("report", report_node)
        graph.add_node("memory", memory_node)

        graph.set_entry_point("plan")
        graph.add_edge("plan", "recon")
        graph.add_edge("recon", "analyze")
        graph.add_edge("analyze", "hypothesize")
        graph.add_edge("hypothesize", "test")
        graph.add_edge("test", "triage")
        graph.add_edge("triage", "report")
        graph.add_edge("report", "memory")

        graph.add_conditional_edges("memory", should_continue, {"plan": "plan", "end": END})

        return graph.compile()

    async def run_autonomous_session(workspace_id: str, session_id: str, targets: list[str],
                                      max_cycles: int = 3) -> SwarmState:
        """Run a full autonomous scanning session."""
        from reconx_shared.db.redis import RedisManager
        import asyncio
        
        redis_mgr = RedisManager()
        graph = build_swarm_graph()
        initial = create_initial_state(workspace_id, session_id, targets, max_cycles)

        logger.info("Autonomous session started", workspace=workspace_id, session=session_id)

        try:
            final_state = initial
            async for s in graph.astream(initial, stream_mode="values"):
                progress = (s.get("cycle", 0) / max_cycles) * 100 if max_cycles else 0
                
                await redis_mgr.set_scan_progress(
                    session_id,
                    s.get("phase", "running"),
                    min(progress, 100.0),
                    {
                        "reasoning_chain": s.get("reasoning_chain", []),
                        "findings": len(s.get("findings", [])),
                        "hypotheses": len(s.get("hypotheses", []))
                    }
                )
                await asyncio.sleep(1.0)
                final_state = s

            logger.info("Autonomous session complete", session=session_id)
            
            # One final push at 100%
            await redis_mgr.set_scan_progress(
                session_id, "complete", 100.0,
                {
                    "reasoning_chain": final_state.get("reasoning_chain", []),
                    "findings": len(final_state.get("findings", [])),
                    "hypotheses": len(final_state.get("hypotheses", []))
                }
            )
            return final_state
        except Exception as e:
            logger.error("Session failed", error=str(e))
            return initial

except ImportError:
    logger.warning("LangGraph not available — using fallback sequential execution")

    async def run_autonomous_session(workspace_id: str, session_id: str, targets: list[str],
                                      max_cycles: int = 3) -> dict:
        from reconx_shared.db.redis import RedisManager
        import asyncio
        from src.agents.swarm import (
            create_initial_state, PlannerAgent, ReconAgent, AnalysisAgent,
            HypothesisAgent, MemoryAgent,
        )
        redis_mgr = RedisManager()
        state = create_initial_state(workspace_id, session_id, targets, max_cycles)
        agents = [PlannerAgent(), ReconAgent(), AnalysisAgent(), HypothesisAgent(), MemoryAgent()]
        
        for cycle in range(max_cycles):
            for agent in agents:
                state = await agent.execute(state)
                progress = (cycle / max_cycles) * 100
                await redis_mgr.set_scan_progress(
                    session_id, state.get("phase", "running"), progress,
                    {
                        "reasoning_chain": state.get("reasoning_chain", []),
                        "findings": len(state.get("findings", [])),
                        "hypotheses": len(state.get("hypotheses", []))
                    }
                )
                await asyncio.sleep(1.0)
                
        await redis_mgr.set_scan_progress(session_id, "complete", 100.0, {
            "reasoning_chain": state.get("reasoning_chain", []),
            "findings": len(state.get("findings", [])),
            "hypotheses": len(state.get("hypotheses", []))
        })
        return state
