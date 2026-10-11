"""LangGraph cyclic state machine orchestrator for Autonomous Security Agent."""

import logging
from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from src.core.edges import route_after_validation
from src.core.nodes import AgentWorkflowNodes
from src.core.state import AgentState

logger = logging.getLogger(__name__)


def build_security_agent_graph(
    nodes: AgentWorkflowNodes | None = None,
) -> CompiledStateGraph:
    """Construct and compile the LangGraph cyclic state machine."""
    workflow_nodes = nodes or AgentWorkflowNodes()

    builder = StateGraph(AgentState)

    # 1. Register Nodes
    builder.add_node("triage_error", workflow_nodes.triage_error_node)
    builder.add_node("fetch_context", workflow_nodes.fetch_context_node)
    builder.add_node("generate_fix", workflow_nodes.generate_fix_node)
    builder.add_node("validate_fix", workflow_nodes.validate_fix_node)
    builder.add_node("create_pr", workflow_nodes.create_pr_node)
    builder.add_node("escalate_to_human", workflow_nodes.escalate_to_human_node)

    # 2. Sequential Edges
    builder.add_edge(START, "triage_error")
    builder.add_edge("triage_error", "fetch_context")
    builder.add_edge("fetch_context", "generate_fix")
    builder.add_edge("generate_fix", "validate_fix")

    # 3. Conditional Self-Correction Loop / Circuit Breaker Router
    builder.add_conditional_edges(
        "validate_fix",
        route_after_validation,
        {
            "create_pr": "create_pr",
            "generate_fix": "generate_fix",
            "escalate_to_human": "escalate_to_human",
        },
    )

    # 4. Terminal Edges
    builder.add_edge("create_pr", END)
    builder.add_edge("escalate_to_human", END)

    return builder.compile()


class SecurityAgentOrchestrator:
    """High-level asynchronous orchestrator for autonomous vulnerability remediation."""

    def __init__(
        self,
        nodes: AgentWorkflowNodes | None = None,
        compiled_graph: CompiledStateGraph | None = None,
    ):
        self.nodes = nodes or AgentWorkflowNodes()
        self.graph = compiled_graph or build_security_agent_graph(self.nodes)

    async def run(
        self,
        error_log: str,
        target_file_path: str | None = None,
        vulnerability_type: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> AgentState:
        """Execute the security agent workflow asynchronously from error log to PR."""
        logger.info("Starting Autonomous Security Agent run...")
        initial_state = AgentState(
            error_log=error_log,
            target_file_path=target_file_path,
            vulnerability_type=vulnerability_type,
        )

        run_config = config or {}
        # Execute cyclic LangGraph state machine
        final_state_dict = await self.graph.ainvoke(
            initial_state.model_dump(), config=run_config
        )

        final_state = AgentState(**final_state_dict)
        logger.info(
            "Agent run finished. Loops: %d, PR: %s, Circuit Breaker: %s",
            final_state.loop_counter,
            bool(final_state.pr_info),
            final_state.circuit_breaker_triggered,
        )
        return final_state
