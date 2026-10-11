"""Unit tests for Resilient MCP Client Gateway and Tool-Calling Validation Interceptor."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.clients.mcp_gateway import MCPGateway
from src.mcp_servers.git_server import GitService
from src.mcp_servers.knowledge_server import KnowledgeGraphService
from src.mcp_servers.sandbox_server import DockerSandboxService


@pytest.fixture
def mock_git_service():
    """Create mock GitService."""
    service = MagicMock(spec=GitService)
    service.read_file = AsyncMock(return_value="000001 | print('hello')")
    service.list_directory = AsyncMock(return_value=["service.py", "views.py"])
    service.create_branch = AsyncMock(return_value="Branch created")
    service.apply_git_diff = AsyncMock(return_value="Diff applied")
    service.create_pull_request = AsyncMock(
        return_value={"status": "OPEN", "url": "https://pr"}
    )
    return service


@pytest.fixture
def mock_sandbox_service():
    """Create mock DockerSandboxService."""
    service = MagicMock(spec=DockerSandboxService)
    service.run_test_in_sandbox = AsyncMock(
        return_value={"exit_code": 0, "status": "PASSED", "stdout": "All tests passed"}
    )
    service.cleanup_sandbox = AsyncMock(return_value=True)
    return service


@pytest.fixture
def mock_knowledge_service():
    """Create mock KnowledgeGraphService."""
    service = MagicMock(spec=KnowledgeGraphService)
    service.get_service_dependencies = AsyncMock(return_value=["db_cluster"])
    service.get_impact_radius = AsyncMock(
        return_value={"target_file": "service.py", "dependent_files": ["router.py"]}
    )
    service.semantic_code_search = AsyncMock(
        return_value=[{"title": "SQLi Guide", "score": 0.95}]
    )
    return service


@pytest.fixture
def gateway(mock_git_service, mock_sandbox_service, mock_knowledge_service):
    """Fixture providing initialized MCPGateway."""
    return MCPGateway(
        git_service=mock_git_service,
        sandbox_service=mock_sandbox_service,
        knowledge_service=mock_knowledge_service,
    )


@pytest.mark.asyncio
async def test_valid_tool_execution(gateway: MCPGateway, mock_git_service):
    """Verify normal valid tool call executes successfully."""
    result = await gateway.execute_tool(
        tool_name="read_file",
        arguments={
            "file_path": "services/auth/service.py",
            "start_line": 1,
            "end_line": 10,
        },
    )

    assert result.success is True
    assert result.is_hallucination is False
    assert result.error_message is None
    assert result.guidance_for_model is None
    assert "print('hello')" in result.output
    mock_git_service.read_file.assert_called_once_with(
        file_path="services/auth/service.py",
        start_line=1,
        end_line=10,
    )


@pytest.mark.asyncio
async def test_parameter_hallucination_intercepted(
    gateway: MCPGateway, mock_git_service
):
    """Verify extra/hallucinated parameters are intercepted and formatted into guidance."""
    # LLM hallucinates `revision="latest"` and `commit_sha="abc123"`
    result = await gateway.execute_tool(
        tool_name="read_file",
        arguments={
            "file_path": "services/auth/service.py",
            "revision": "latest",
            "commit_sha": "abc123",
        },
    )

    # Must NOT crash, must flag hallucination, and return clear guidance
    assert result.success is False
    assert result.is_hallucination is True
    assert "revision" in result.guidance_for_model
    assert "commit_sha" in result.guidance_for_model
    assert "Valid arguments for 'read_file' are" in result.guidance_for_model
    # Handler should NOT have been invoked with hallucinated arguments
    mock_git_service.read_file.assert_not_called()


@pytest.mark.asyncio
async def test_tool_name_hallucination_intercepted(gateway: MCPGateway):
    """Verify non-existent tool calls are intercepted and available tools are suggested."""
    result = await gateway.execute_tool(
        tool_name="fetch_source_code_from_remote",
        arguments={"path": "src/main.py"},
    )

    assert result.success is False
    assert result.is_hallucination is True
    assert (
        "Tool 'fetch_source_code_from_remote' does not exist"
        in result.guidance_for_model
    )
    assert "Available tools are:" in result.guidance_for_model
    assert "read_file" in result.guidance_for_model


@pytest.mark.asyncio
async def test_execution_exception_handled_as_guidance(
    gateway: MCPGateway, mock_sandbox_service
):
    """Verify handler exceptions are caught and converted to model guidance."""
    mock_sandbox_service.run_test_in_sandbox.side_effect = RuntimeError(
        "Container OOM killed"
    )

    result = await gateway.execute_tool(
        tool_name="run_test_in_sandbox",
        arguments={"service_name": "auth_service", "test_command": "pytest"},
    )

    assert result.success is False
    assert result.is_hallucination is False
    assert "Container OOM killed" in result.error_message
    assert (
        "Error executing 'run_test_in_sandbox': RuntimeError"
        in result.guidance_for_model
    )


def test_get_tool_signatures(gateway: MCPGateway):
    """Verify tool signatures produce valid Claude/Bedrock-compatible JSON schemas."""
    signatures = gateway.get_tool_signatures()
    assert len(signatures) >= 8

    tool_names = [sig["toolSpec"]["name"] for sig in signatures]
    assert "read_file" in tool_names
    assert "run_test_in_sandbox" in tool_names
    assert "get_service_dependencies" in tool_names

    # Check input schema on read_file
    read_file_sig = next(s for s in signatures if s["toolSpec"]["name"] == "read_file")
    props = read_file_sig["toolSpec"]["inputSchema"]["json"]["properties"]
    assert "file_path" in props
    assert "start_line" in props
    assert "end_line" in props
