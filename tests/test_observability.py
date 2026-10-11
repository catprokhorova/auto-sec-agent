"""Unit tests for Langfuse observability, telemetry tracing, and agentic metrics."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.clients.bedrock import BedrockClient, LLMResponse
from src.clients.langfuse_tracer import (
    CLAUDE_35_HAIKU_INPUT_PER_1M,
    CLAUDE_35_HAIKU_OUTPUT_PER_1M,
    CLAUDE_35_SONNET_INPUT_PER_1M,
    CLAUDE_35_SONNET_OUTPUT_PER_1M,
    LangfuseTracer,
)
from src.clients.mcp_gateway import MCPGateway
from src.core.nodes import AgentWorkflowNodes
from src.core.orchestrator import SecurityAgentOrchestrator


def test_cost_calculation():
    """Verify Bedrock token cost calculations for Sonnet and Haiku."""
    tracer = LangfuseTracer()

    # 10,000 input tokens, 2,000 output tokens for Sonnet
    sonnet_cost = tracer.calculate_cost(
        model="anthropic.claude-3-5-sonnet",
        input_tokens=10_000,
        output_tokens=2_000,
    )
    expected_sonnet = (10_000 * CLAUDE_35_SONNET_INPUT_PER_1M / 1_000_000) + (
        2_000 * CLAUDE_35_SONNET_OUTPUT_PER_1M / 1_000_000
    )
    assert pytest.approx(sonnet_cost, 1e-6) == expected_sonnet

    # 10,000 input tokens, 2,000 output tokens for Haiku
    haiku_cost = tracer.calculate_cost(
        model="anthropic.claude-3-5-haiku",
        input_tokens=10_000,
        output_tokens=2_000,
    )
    expected_haiku = (10_000 * CLAUDE_35_HAIKU_INPUT_PER_1M / 1_000_000) + (
        2_000 * CLAUDE_35_HAIKU_OUTPUT_PER_1M / 1_000_000
    )
    assert pytest.approx(haiku_cost, 1e-6) == expected_haiku


def test_tracer_metrics_optimal_trajectory():
    """Verify metrics calculation for an optimal 5-step trajectory."""
    tracer = LangfuseTracer()
    trace_id = tracer.start_trace(name="test-run")

    # Log 5 standard optimal steps
    steps = [
        "triage_error",
        "fetch_context",
        "generate_fix",
        "validate_fix",
        "create_pr",
    ]
    for s in steps:
        tracer.log_node_execution(trace_id=trace_id, node_name=s)

    # Log tool calls (all successful)
    tracer.log_tool_call(
        trace_id=trace_id,
        tool_name="read_file",
        arguments={"file_path": "a.py"},
        success=True,
    )
    tracer.log_tool_call(
        trace_id=trace_id,
        tool_name="run_test_in_sandbox",
        arguments={},
        success=True,
    )

    # Record token usage
    tracer.record_token_usage(
        trace_id=trace_id,
        model="haiku",
        input_tokens=500,
        output_tokens=100,
    )
    tracer.record_token_usage(
        trace_id=trace_id,
        model="sonnet",
        input_tokens=2000,
        output_tokens=400,
    )

    metrics = tracer.get_metrics(trace_id)

    assert metrics["is_optimal_trajectory"] is True
    assert metrics["step_count"] == 5
    assert metrics["trajectory_consistency_score"] == 1.0
    assert metrics["tool_calling_accuracy"] == 1.0
    assert metrics["successful_tool_calls"] == 2
    assert metrics["hallucinated_tool_calls"] == 0
    assert metrics["circuit_breaker_triggered"] is False
    assert metrics["total_cost_usd"] > 0.0


def test_tracer_metrics_tool_hallucination_and_circuit_breaker():
    """Verify metrics reflect intercepted tool hallucinations and circuit breaker trips."""
    tracer = LangfuseTracer()
    trace_id = tracer.start_trace(name="failing-run")

    # Log a hallucinated tool call followed by a corrected tool call
    tracer.log_tool_call(
        trace_id=trace_id,
        tool_name="read_nonexistent_tool",
        arguments={},
        success=False,
        is_hallucination=True,
        error_message="Tool not found",
    )
    tracer.log_tool_call(
        trace_id=trace_id,
        tool_name="read_file",
        arguments={"file_path": "test.py"},
        success=True,
    )

    # Log circuit breaker event
    tracer.log_circuit_breaker(
        trace_id=trace_id,
        reason="Maximum remediation attempts exceeded (3/3)",
        loop_counter=3,
    )

    metrics = tracer.get_metrics(trace_id)

    assert metrics["total_tool_calls"] == 2
    assert metrics["successful_tool_calls"] == 1
    assert metrics["hallucinated_tool_calls"] == 1
    assert metrics["tool_calling_accuracy"] == 0.5
    assert metrics["circuit_breaker_triggered"] is True
    assert "Maximum remediation attempts exceeded" in metrics["circuit_breaker_reason"]


@pytest.mark.asyncio
async def test_orchestrator_end_to_end_telemetry(sample_python_traceback: str):
    """Verify that SecurityAgentOrchestrator populates tracer metrics on full execution."""
    tracer = LangfuseTracer()

    # Bedrock mock
    mock_bedrock = MagicMock(spec=BedrockClient)
    mock_bedrock.generate_haiku = AsyncMock(
        return_value=LLMResponse(
            content='{"target_file": "app.py", "line_number": 10, "vulnerability_type": "SQLi"}',
            input_tokens=150,
            output_tokens=40,
            model="haiku",
        )
    )
    mock_bedrock.generate_sonnet = AsyncMock(
        return_value=LLMResponse(
            content="```diff\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+fixed\n```",
            input_tokens=800,
            output_tokens=200,
            model="sonnet",
        )
    )

    # Gateway mock
    mock_gateway = MagicMock(spec=MCPGateway)

    async def _mock_tool(tool_name: str, _arguments: dict | None = None):
        res = MagicMock()
        res.success = True
        res.is_hallucination = False
        res.error_message = None
        if tool_name == "run_test_in_sandbox":
            res.output = {"exit_code": 0, "status": "PASSED"}
        elif tool_name == "create_pull_request":
            res.output = {"status": "OPEN", "url": "https://pr/1"}
        elif tool_name == "read_file":
            res.output = "def authenticate(): pass"
        elif tool_name == "get_impact_radius":
            res.output = {"affected_services": ["auth"]}
        elif tool_name == "semantic_code_search":
            res.output = [{"title": "Doc", "snippet": "Guidelines"}]
        else:
            res.output = "OK"
        return res

    mock_gateway.execute_tool = AsyncMock(side_effect=_mock_tool)
    mock_gateway.current_trace_id = None

    nodes = AgentWorkflowNodes(
        bedrock_client=mock_bedrock,
        mcp_gateway=mock_gateway,
        tracer=tracer,
    )
    orch = SecurityAgentOrchestrator(nodes=nodes, tracer=tracer)

    final_state = await orch.run(error_log=sample_python_traceback)

    assert final_state.trace_id is not None
    metrics = tracer.get_metrics(final_state.trace_id)

    assert metrics["is_optimal_trajectory"] is True
    assert metrics["step_count"] == 5
    assert metrics["trajectory_steps"] == [
        "triage_error",
        "fetch_context",
        "generate_fix",
        "validate_fix",
        "create_pr",
    ]
    assert metrics["total_cost_usd"] > 0.0
