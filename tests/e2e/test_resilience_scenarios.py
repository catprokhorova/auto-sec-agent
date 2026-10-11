"""End-to-end resilience demonstration tests verifying core architectural defenses.

Scenarios covered:
- Scenario A: Clean fix on 1st iteration (Optimal 5-step trajectory).
- Scenario B: Self-correction loop (Attempt 1 fails tests, Attempt 2 succeeds).
- Scenario C: Hard loop circuit breaker (Persistent failures trip breaker and escalate).
- Scenario D: Tool hallucination intercept (Parameter/tool hallucinations intercepted safely).
- Scenario E: CI/CD Webhook pipeline integration (FastAPI /webhook/ci synchronous & async).
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.clients.bedrock import BedrockClient, LLMResponse
from src.clients.langfuse_tracer import LangfuseTracer
from src.clients.mcp_gateway import MCPGateway
from src.core.config import Settings
from src.core.nodes import AgentWorkflowNodes
from src.core.orchestrator import SecurityAgentOrchestrator

VULNERABLE_SQLI_LOG = """
[ERROR] CI/CD Pipeline Job #9104 FAILED
=================================== FAILURES ===================================
_____________________ test_sql_injection_bypass_prevented ______________________
    def test_sql_injection_bypass_prevented():
>       user = auth_service.authenticate_user("random_user", "' OR '1'='1")
E       AssertionError: Vulnerability detected: SQL injection authentication bypass succeeded!
E       assert {'id': '1', 'role': 'admin', 'username': 'admin'} is None
playground/auth_service/test_service.py:36: AssertionError
=========================== short test summary info ============================
FAILED playground/auth_service/test_service.py::test_sql_injection_bypass_prevented
"""


def _create_mock_gateway(sandbox_result_fn: Any) -> MCPGateway:
    """Helper creating a mock MCPGateway returning proper data types."""
    gateway = MagicMock(spec=MCPGateway)
    gateway.current_trace_id = None

    async def _tool_exec(tool_name: str, _arguments: dict | None = None):
        res = MagicMock()
        res.success = True
        res.is_hallucination = False
        res.error_message = None
        if tool_name == "run_test_in_sandbox":
            if callable(sandbox_result_fn):
                res.output = sandbox_result_fn()
            else:
                res.output = sandbox_result_fn
        elif tool_name == "create_pull_request":
            res.output = {
                "status": "OPEN",
                "url": "https://gitlab.com/petty-pets/auto-sec-agent/-/merge_requests/101",
            }
        elif tool_name == "read_file":
            res.output = "def authenticate_user(u, p):\n    query = f'SELECT * FROM users WHERE u={u}'"
        elif tool_name == "get_impact_radius":
            res.output = {
                "affected_services": ["auth_service"],
                "suggested_test_suites": ["playground/auth_service/test_service.py"],
            }
        elif tool_name == "semantic_code_search":
            res.output = [
                {"title": "CWE-89 Remediation", "snippet": "Use DB parameter binding"}
            ]
        else:
            res.output = "OK"
        return res

    gateway.execute_tool = AsyncMock(side_effect=_tool_exec)
    return gateway


@pytest.mark.asyncio
async def test_scenario_a_optimal_five_step_trajectory():
    """Scenario A: Clean fix on 1st iteration (Optimal 5-step trajectory)."""
    tracer = LangfuseTracer()

    mock_bedrock = MagicMock(spec=BedrockClient)
    mock_bedrock.generate_haiku = AsyncMock(
        return_value=LLMResponse(
            content='{"target_file": "playground/auth_service/service.py", "line_number": 38, "vulnerability_type": "CWE-89: SQL Injection"}',
            input_tokens=200,
            output_tokens=50,
            model="haiku",
        )
    )
    mock_bedrock.generate_sonnet = AsyncMock(
        return_value=LLMResponse(
            content=(
                "```diff\n"
                "--- a/playground/auth_service/service.py\n"
                "+++ b/playground/auth_service/service.py\n"
                "@@ -38,2 +38,2 @@\n"
                "-        query = f'SELECT * FROM users WHERE username = \\'{username}\\' AND password = \\'{password}\\''\n"
                "-        cursor.execute(query)\n"
                "+        query = 'SELECT * FROM users WHERE username = ? AND password = ?'\n"
                "+        cursor.execute(query, (username, password))\n"
                "```"
            ),
            input_tokens=1100,
            output_tokens=220,
            model="sonnet",
        )
    )

    mock_gateway = _create_mock_gateway({"exit_code": 0, "status": "PASSED"})
    nodes = AgentWorkflowNodes(
        bedrock_client=mock_bedrock,
        mcp_gateway=mock_gateway,
        tracer=tracer,
    )
    orch = SecurityAgentOrchestrator(nodes=nodes, tracer=tracer)

    final_state = await orch.run(error_log=VULNERABLE_SQLI_LOG)

    assert final_state.circuit_breaker_triggered is False
    assert final_state.loop_counter == 1
    assert final_state.pr_info is not None
    assert final_state.pr_info["status"] == "OPEN"

    metrics = tracer.get_metrics(final_state.trace_id or "")
    assert metrics["is_optimal_trajectory"] is True
    assert metrics["step_count"] == 5
    assert metrics["trajectory_steps"] == [
        "triage_error",
        "fetch_context",
        "generate_fix",
        "validate_fix",
        "create_pr",
    ]


@pytest.mark.asyncio
async def test_scenario_b_self_correction_loop():
    """Scenario B: Self-correction loop where attempt 1 fails tests, but attempt 2 passes."""
    tracer = LangfuseTracer()
    attempt = 0

    def _sandbox_attempt():
        nonlocal attempt
        attempt += 1
        if attempt == 1:
            return {
                "exit_code": 1,
                "status": "FAILED",
                "stderr": "sqlite3.ProgrammingError: Incorrect number of bindings supplied.",
            }
        return {"exit_code": 0, "status": "PASSED", "stdout": "3 passed in 0.2s"}

    mock_bedrock = MagicMock(spec=BedrockClient)
    mock_bedrock.generate_haiku = AsyncMock(
        return_value=LLMResponse(
            content='{"target_file": "playground/auth_service/service.py", "line_number": 38, "vulnerability_type": "CWE-89"}',
            input_tokens=200,
            output_tokens=50,
            model="haiku",
        )
    )

    patch_v1 = "```diff\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-broken\n+bad_param_count\n```"
    patch_v2 = (
        "```diff\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-broken\n+correct_param_binding\n```"
    )
    mock_bedrock.generate_sonnet = AsyncMock(
        side_effect=[
            LLMResponse(
                content=patch_v1, input_tokens=1000, output_tokens=200, model="sonnet"
            ),
            LLMResponse(
                content=patch_v2, input_tokens=1400, output_tokens=240, model="sonnet"
            ),
        ]
    )

    mock_gateway = _create_mock_gateway(_sandbox_attempt)
    nodes = AgentWorkflowNodes(
        bedrock_client=mock_bedrock,
        mcp_gateway=mock_gateway,
        tracer=tracer,
    )
    orch = SecurityAgentOrchestrator(nodes=nodes, tracer=tracer)

    final_state = await orch.run(error_log=VULNERABLE_SQLI_LOG)

    assert final_state.circuit_breaker_triggered is False
    assert final_state.loop_counter == 2
    assert final_state.pr_info is not None
    assert len(final_state.patch_history) == 2

    metrics = tracer.get_metrics(final_state.trace_id or "")
    assert metrics["step_count"] == 7
    assert metrics["trajectory_steps"] == [
        "triage_error",
        "fetch_context",
        "generate_fix",
        "validate_fix",
        "generate_fix",
        "validate_fix",
        "create_pr",
    ]


@pytest.mark.asyncio
async def test_scenario_c_hard_loop_circuit_breaker():
    """Scenario C: Hard loop circuit breaker terminates execution after attempt threshold."""
    tracer = LangfuseTracer()

    mock_bedrock = MagicMock(spec=BedrockClient)
    mock_bedrock.generate_haiku = AsyncMock(
        return_value=LLMResponse(
            content='{"target_file": "app.py", "line_number": 1, "vulnerability_type": "CWE-89"}',
            input_tokens=100,
            output_tokens=30,
            model="haiku",
        )
    )

    diffs = [
        f"```diff\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n+try_{i}\n```" for i in range(5)
    ]
    mock_bedrock.generate_sonnet = AsyncMock(
        side_effect=[
            LLMResponse(content=d, input_tokens=800, output_tokens=150, model="sonnet")
            for d in diffs
        ]
    )

    mock_gateway = _create_mock_gateway(
        {"exit_code": 1, "status": "FAILED", "stderr": "Error"}
    )
    settings = Settings(max_loop_count=3)
    nodes = AgentWorkflowNodes(
        bedrock_client=mock_bedrock,
        mcp_gateway=mock_gateway,
        tracer=tracer,
        settings=settings,
    )
    orch = SecurityAgentOrchestrator(nodes=nodes, tracer=tracer)

    final_state = await orch.run(error_log=VULNERABLE_SQLI_LOG)

    # Hard circuit breaker verification
    assert final_state.circuit_breaker_triggered is True
    assert final_state.loop_counter == 3
    assert final_state.pr_info is None
    assert final_state.escalation_reason is not None
    assert "attempts exceeded" in final_state.escalation_reason.lower()

    metrics = tracer.get_metrics(final_state.trace_id or "")
    assert metrics["circuit_breaker_triggered"] is True
    assert metrics["trajectory_steps"][-1] == "escalate_to_human"


@pytest.mark.asyncio
async def test_scenario_d_tool_hallucination_recovery():
    """Scenario D: Tool hallucination interceptor prevents crashes and guides model."""
    gateway = MCPGateway()

    # 1. Hallucinated tool name
    bad_tool_res = await gateway.execute_tool(
        "read_code_from_branch",
        {"file_path": "a.py"},
    )
    assert bad_tool_res.success is False
    assert bad_tool_res.is_hallucination is True
    assert "Available tools are" in bad_tool_res.guidance_for_model

    # 2. Hallucinated extra argument
    bad_arg_res = await gateway.execute_tool(
        "read_file",
        {"file_path": "a.py", "revision": "latest"},
    )
    assert bad_arg_res.success is False
    assert bad_arg_res.is_hallucination is True
    assert "hallucinated parameter" in bad_arg_res.guidance_for_model
    assert "revision" in bad_arg_res.guidance_for_model


def test_scenario_e_fastapi_webhook_integration():
    """Scenario E: FastAPI webhook trigger (/webhook/ci) handles valid pipeline events."""
    client = TestClient(app)

    # 1. Health check
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "healthy"

    # 2. Async background trigger
    async_payload = {
        "provider": "gitlab",
        "repo": "petty-pets/auto-sec-agent",
        "branch": "main",
        "error_log": VULNERABLE_SQLI_LOG,
        "async_execution": True,
    }
    resp = client.post("/webhook/ci", json=async_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ACCEPTED"
    assert "run_id" in data
    assert "trace_id" in data
