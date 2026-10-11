"""LangGraph cyclic state machine orchestrator for Autonomous Security Agent."""

import logging
from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from src.clients.langfuse_tracer import LangfuseTracer
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
        tracer: LangfuseTracer | None = None,
    ):
        self.tracer = tracer or LangfuseTracer()
        self.nodes = nodes or AgentWorkflowNodes(tracer=self.tracer)
        if hasattr(self.nodes, "tracer") and self.nodes.tracer is None:
            self.nodes.tracer = self.tracer
            if hasattr(self.nodes, "gateway") and self.nodes.gateway:
                self.nodes.gateway.set_tracer(self.tracer)

        self.graph = compiled_graph or build_security_agent_graph(self.nodes)

    async def run(
        self,
        error_log: str,
        target_file_path: str | None = None,
        vulnerability_type: str | None = None,
        config: dict[str, Any] | None = None,
        trace_id: str | None = None,
    ) -> AgentState:
        """Execute the security agent workflow asynchronously from error log to PR."""
        logger.info("Starting Autonomous Security Agent run...")

        # 1. Start execution trace in Langfuse / In-memory tracer
        active_trace_id = self.tracer.start_trace(
            name="security-agent-run",
            metadata={
                "target_file_path": target_file_path,
                "vulnerability_type": vulnerability_type,
            },
            tags=["autonomous-security-agent", "ci-pipeline"],
            trace_id=trace_id,
        )

        initial_state = AgentState(
            error_log=error_log,
            target_file_path=target_file_path,
            vulnerability_type=vulnerability_type,
            trace_id=active_trace_id,
        )

        run_config = dict(config or {})
        cb = self.tracer.get_langchain_callback()
        if cb:
            run_config.setdefault("callbacks", []).append(cb)

        # 2. Execute cyclic LangGraph state machine step-by-step
        accumulated_state = initial_state.model_dump()
        async for step_dict in self.graph.astream(
            initial_state.model_dump(), config=run_config, stream_mode="updates"
        ):
            for node_name, updated_fields in step_dict.items():
                accumulated_state.update(updated_fields)
                self.tracer.log_node_execution(
                    trace_id=active_trace_id,
                    node_name=node_name,
                    outputs=updated_fields,
                )

        self.tracer.flush()

        final_state = AgentState(**accumulated_state)
        logger.info(
            "Agent run finished. Loops: %d, PR: %s, Circuit Breaker: %s, Trace: %s",
            final_state.loop_counter,
            bool(final_state.pr_info),
            final_state.circuit_breaker_triggered,
            active_trace_id,
        )
        return final_state
