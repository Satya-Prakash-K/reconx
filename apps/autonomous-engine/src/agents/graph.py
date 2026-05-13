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
            state["reasoning_chain"].append("[testing] Executing test payloads against hypotheses")
            # Integration point — calls vuln-engine modules
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

    async def run_autonomous_session(workspace_id: str, targets: list[str],
                                      max_cycles: int = 3) -> SwarmState:
        """Run a full autonomous scanning session."""
        graph = build_swarm_graph()
        initial = create_initial_state(workspace_id, targets, max_cycles)

        logger.info("Autonomous session started", workspace=workspace_id,
                     targets=len(targets), max_cycles=max_cycles)

        result = await graph.ainvoke(initial)

        logger.info("Autonomous session complete",
                     cycles=result.get("cycle", 0),
                     findings=len(result.get("findings", [])),
                     reasoning_steps=len(result.get("reasoning_chain", [])))
        return result

except ImportError:
    logger.warning("LangGraph not available — using fallback sequential execution")

    async def run_autonomous_session(workspace_id: str, targets: list[str],
                                      max_cycles: int = 3) -> dict:
        from src.agents.swarm import (
            create_initial_state, PlannerAgent, ReconAgent, AnalysisAgent,
            HypothesisAgent, MemoryAgent,
        )
        state = create_initial_state(workspace_id, targets, max_cycles)
        agents = [PlannerAgent(), ReconAgent(), AnalysisAgent(), HypothesisAgent(), MemoryAgent()]
        for cycle in range(max_cycles):
            for agent in agents:
                state = await agent.execute(state)
        return state
