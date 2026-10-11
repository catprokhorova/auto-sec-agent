"""Unit tests for LangGraph StateMachine orchestrator and anti-loop circuit breaker."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.clients.bedrock import BedrockClient, LLMResponse
from src.clients.mcp_gateway import MCPGateway
from src.core.config import Settings
from src.core.edges import route_after_validation
from src.core.nodes import AgentWorkflowNodes
from src.core.orchestrator import SecurityAgentOrchestrator
from src.core.pruner import TokenPruner
from src.core.state import AgentState


@pytest.fixture
def mock_bedrock() -> BedrockClient:
    """Fixture providing a mock BedrockClient with deterministic responses."""
    client = MagicMock(spec=BedrockClient)
    client.generate_haiku = AsyncMock(
        return_value=LLMResponse(
            content=(
                '{"target_file": "services/auth/service.py", '
                '"line_number": 18, '
                '"vulnerability_type": "CWE-89: SQL Injection", '
                '"summary": "Direct parameter interpolation"}'
            ),
            stop_reason="end_turn",
            input_tokens=100,
            output_tokens=50,
            model="haiku",
        )
    )
    client.generate_sonnet = AsyncMock(
        return_value=LLMResponse(
            content=(
                "```diff\n"
                "--- a/services/auth/service.py\n"
                "+++ b/services/auth/service.py\n"
                "@@ -17,2 +17,2 @@\n"
                "-    cursor.execute(f'SELECT * FROM users WHERE u={u}')\n"
                "+    cursor.execute('SELECT * FROM users WHERE u=?', (u,))\n"
                "```"
            ),
            stop_reason="end_turn",
            input_tokens=250,
            output_tokens=80,
            model="sonnet",
        )
    )
    return client


@pytest.fixture
def mock_mcp_gateway() -> MCPGateway:
    """Fixture providing a mock MCPGateway."""
    gw = MagicMock(spec=MCPGateway)

    async def _mock_exec(tool_name: str, arguments: dict = None):
        res = MagicMock()
        res.success = True
        res.error_message = None

        if tool_name == "get_impact_radius":
            res.output = {
                "affected_services": ["auth_service"],
                "suggested_test_suites": ["tests/test_auth.py"],
            }
        elif tool_name == "read_file":
            res.output = "000018 | cursor.execute(query)"
        elif tool_name == "semantic_code_search":
            res.output = [{"title": "SQLi Prevention", "snippet": "Use parameters"}]
        elif tool_name == "run_test_in_sandbox":
            res.output = {
                "exit_code": 0,
                "status": "PASSED",
                "stdout": "1 passed in 0.05s",
                "stderr": "",
            }
        elif tool_name in ["create_branch", "apply_git_diff"]:
            res.output = "OK"
        elif tool_name == "create_pull_request":
            res.output = {
                "title": arguments.get("title") if arguments else "PR",
                "status": "OPEN",
                "url": "https://gitlab.com/repo/-/merge_requests/42",
            }
        return res

    gw.execute_tool = AsyncMock(side_effect=_mock_exec)
    return gw


@pytest.fixture
def orchestrator(
    mock_bedrock: BedrockClient, mock_mcp_gateway: MCPGateway
) -> SecurityAgentOrchestrator:
    """Fixture providing configured SecurityAgentOrchestrator."""
    settings = Settings(max_loop_count=3)
    pruner = TokenPruner(max_lines=100)
    nodes = AgentWorkflowNodes(
        bedrock_client=mock_bedrock,
        mcp_gateway=mock_mcp_gateway,
        pruner=pruner,
        settings=settings,
    )
    return SecurityAgentOrchestrator(nodes=nodes)


# ---------------------------------------------------------------------------
# Edge Router Unit Tests
# ---------------------------------------------------------------------------


def test_route_after_validation_passed():
    """Verify route to 'create_pr' when sandbox tests pass."""
    state = AgentState(
        error_log="err",
        loop_counter=1,
        test_reproduction_result={"status": "PASSED", "exit_code": 0},
    )
    assert route_after_validation(state) == "create_pr"


def test_route_after_validation_retry_loop():
    """Verify route back to 'generate_fix' when tests fail but loop limit is not reached."""
    state = AgentState(
        error_log="err",
        loop_counter=1,
        patch_history=["hash_attempt_1"],
        test_reproduction_result={"status": "FAILED", "exit_code": 1},
    )
    assert route_after_validation(state) == "generate_fix"


def test_route_after_validation_max_loop_circuit_breaker():
    """Verify circuit breaker routes to 'escalate_to_human' when loop_counter reaches limit."""
    state = AgentState(
        error_log="err",
        loop_counter=3,  # limit is 3
        patch_history=["h1", "h2", "h3"],
        test_reproduction_result={"status": "FAILED", "exit_code": 1},
    )
    assert route_after_validation(state) == "escalate_to_human"


def test_route_after_validation_duplicate_patch_circuit_breaker():
    """Verify circuit breaker trips when a duplicate patch hash is detected."""
    state = AgentState(
        error_log="err",
        loop_counter=2,  # below limit of 3
        patch_history=["hash_a", "hash_b", "hash_a"],  # hash_a repeated!
        test_reproduction_result={"status": "FAILED", "exit_code": 1},
    )
    assert route_after_validation(state) == "escalate_to_human"


# ---------------------------------------------------------------------------
# End-to-End Graph Trajectory Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_trajectory(
    orchestrator: SecurityAgentOrchestrator, sample_python_traceback: str
):
    """Test optimal 1-attempt trajectory: Triage -> Fetch -> Fix -> Validate -> Create PR."""
    final_state = await orchestrator.run(error_log=sample_python_traceback)

    assert final_state.circuit_breaker_triggered is False
    assert final_state.loop_counter == 1
    assert final_state.target_file_path == "services/auth/service.py"
    assert "CWE-89" in (final_state.vulnerability_type or "")
    assert final_state.proposed_patch is not None
    assert final_state.pr_info is not None
    assert final_state.pr_info["status"] == "OPEN"
    assert "merge_requests" in final_state.pr_info["url"]


@pytest.mark.asyncio
async def test_self_correction_loop_trajectory(
    mock_bedrock: BedrockClient,
    mock_mcp_gateway: MCPGateway,
    sample_python_traceback: str,
):
    """Test self-correction loop where attempt 1 fails tests, but attempt 2 succeeds."""
    # Custom sandbox validation: fail on attempt 1, pass on attempt 2
    attempt_counter = 0

    async def _mock_exec_dynamic(tool_name: str, _arguments: dict | None = None):
        nonlocal attempt_counter
        res = MagicMock()
        res.success = True
        res.error_message = None

        if tool_name == "run_test_in_sandbox":
            attempt_counter += 1
            if attempt_counter == 1:
                res.output = {
                    "exit_code": 1,
                    "status": "FAILED",
                    "stdout": "",
                    "stderr": "SyntaxError: invalid syntax on line 18",
                }
            else:
                res.output = {
                    "exit_code": 0,
                    "status": "PASSED",
                    "stdout": "All tests passed",
                    "stderr": "",
                }
        elif tool_name == "get_impact_radius":
            res.output = {"affected_services": ["auth_service"]}
        elif tool_name == "read_file":
            res.output = "def auth(): pass"
        elif tool_name == "semantic_code_search":
            res.output = [{"title": "Doc", "snippet": "Guidelines"}]
        elif tool_name == "create_pull_request":
            res.output = {"status": "OPEN", "url": "https://pr/2"}
        else:
            res.output = "OK"
        return res

    mock_mcp_gateway.execute_tool = AsyncMock(side_effect=_mock_exec_dynamic)

    # Vary the generated diff on attempt 2 to avoid duplicate patch detection
    diff_v1 = "```diff\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-broken\n+bad_syntax\n```"
    diff_v2 = "```diff\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-broken\n+fixed\n```"

    mock_bedrock.generate_sonnet = AsyncMock()
    mock_bedrock.generate_sonnet.side_effect = [
        LLMResponse(content=diff_v1, model="sonnet"),
        LLMResponse(content=diff_v2, model="sonnet"),
    ]

    settings = Settings(max_loop_count=3)
    nodes = AgentWorkflowNodes(
        bedrock_client=mock_bedrock,
        mcp_gateway=mock_mcp_gateway,
        settings=settings,
    )
    orch = SecurityAgentOrchestrator(nodes=nodes)

    final_state = await orch.run(error_log=sample_python_traceback)

    assert final_state.circuit_breaker_triggered is False
    assert final_state.loop_counter == 2
    assert final_state.pr_info is not None
    assert final_state.pr_info["status"] == "OPEN"
    assert len(final_state.patch_history) == 2


@pytest.mark.asyncio
async def test_hard_circuit_breaker_escalation(
    mock_bedrock: BedrockClient,
    mock_mcp_gateway: MCPGateway,
    sample_python_traceback: str,
):
    """Test that after 3 failed attempts, the circuit breaker stops execution and escalates."""

    # Always fail sandbox execution
    async def _mock_always_fail(tool_name: str, _arguments: dict | None = None):
        res = MagicMock()
        res.success = True
        res.error_message = None
        if tool_name == "run_test_in_sandbox":
            res.output = {
                "exit_code": 1,
                "status": "FAILED",
                "stdout": "",
                "stderr": "Persistent failure",
            }
        elif tool_name == "get_impact_radius":
            res.output = {"affected_services": []}
        elif tool_name == "read_file":
            res.output = "code"
        elif tool_name == "semantic_code_search":
            res.output = []
        else:
            res.output = "OK"
        return res

    mock_mcp_gateway.execute_tool = AsyncMock(side_effect=_mock_always_fail)

    # Return distinct diffs for each attempt
    diffs = [
        f"```diff\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-v\n+attempt_{i}\n```"
        for i in range(10)
    ]
    mock_bedrock.generate_sonnet = AsyncMock(
        side_effect=[LLMResponse(content=d, model="sonnet") for d in diffs]
    )

    settings = Settings(max_loop_count=3)
    nodes = AgentWorkflowNodes(
        bedrock_client=mock_bedrock,
        mcp_gateway=mock_mcp_gateway,
        settings=settings,
    )
    orch = SecurityAgentOrchestrator(nodes=nodes)

    final_state = await orch.run(error_log=sample_python_traceback)

    # Verify hard circuit breaker tripped
    assert final_state.circuit_breaker_triggered is True
    assert final_state.loop_counter == 3
    assert final_state.pr_info is None
    assert final_state.escalation_reason is not None


@pytest.mark.asyncio
async def test_duplicate_patch_oscillation_circuit_breaker(
    mock_bedrock: BedrockClient,
    mock_mcp_gateway: MCPGateway,
    sample_python_traceback: str,
):
    """Test that repeating the identical patch immediately trips the circuit breaker."""

    async def _mock_fail(tool_name: str, _arguments: dict | None = None):
        res = MagicMock()
        res.success = True
        res.error_message = None
        if tool_name == "run_test_in_sandbox":
            res.output = {"exit_code": 1, "status": "FAILED", "stderr": "Err"}
        elif tool_name == "get_impact_radius":
            res.output = {"affected_services": []}
        elif tool_name == "read_file":
            res.output = "code"
        elif tool_name == "semantic_code_search":
            res.output = []
        else:
            res.output = "OK"
        return res

    mock_mcp_gateway.execute_tool = AsyncMock(side_effect=_mock_fail)

    # Return identical patch on attempt 1 and attempt 2
    identical_diff = "```diff\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-old\n+identical\n```"
    mock_bedrock.generate_sonnet = AsyncMock(
        return_value=LLMResponse(content=identical_diff, model="sonnet")
    )

    settings = Settings(max_loop_count=5)  # Limit is 5, but should trip at 2!
    nodes = AgentWorkflowNodes(
        bedrock_client=mock_bedrock,
        mcp_gateway=mock_mcp_gateway,
        settings=settings,
    )
    orch = SecurityAgentOrchestrator(nodes=nodes)

    final_state = await orch.run(error_log=sample_python_traceback)

    # Should have stopped after attempt 2 because patch 2 was identical to patch 1
    assert final_state.circuit_breaker_triggered is True
    assert final_state.loop_counter == 2
    assert final_state.pr_info is None
    assert len(final_state.patch_history) == 2
    assert final_state.patch_history[0] == final_state.patch_history[1]
