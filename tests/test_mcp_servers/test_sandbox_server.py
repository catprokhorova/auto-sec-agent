"""Unit tests for MCP Sandbox Server and DockerSandboxService."""

import pytest
from unittest.mock import MagicMock

from src.mcp_servers.sandbox_server import (
    DockerSandboxService,
    create_sandbox_mcp_server,
)


@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client imitating docker SDK behavior."""
    client = MagicMock()
    container = MagicMock()
    container.id = "c1234567890abcdef"
    container.wait.return_value = {"StatusCode": 0}
    container.logs.side_effect = lambda stdout=False, stderr=False: (
        b"5 passed in 0.2s" if stdout else b""
    )
    client.containers.create.return_value = container
    client.containers.get.return_value = container
    return client


@pytest.mark.asyncio
async def test_run_test_in_sandbox_passed(mock_docker_client):
    """Test successful test execution inside sandbox container."""
    service = DockerSandboxService(docker_client=mock_docker_client)
    res = await service.run_test_in_sandbox(
        service_name="auth_service",
        patch_diff="--- a/b\n+++ a/b",
        test_command="pytest",
        timeout_sec=10,
    )

    assert res["status"] == "PASSED"
    assert res["exit_code"] == 0
    assert "5 passed" in res["stdout"]
    assert res["container_id"] == "c1234567890a"
    mock_docker_client.containers.create.assert_called_once()


@pytest.mark.asyncio
async def test_run_test_in_sandbox_failed(mock_docker_client):
    """Test failing test execution in sandbox."""
    container = mock_docker_client.containers.create.return_value
    container.wait.return_value = {"StatusCode": 1}
    container.logs.side_effect = lambda stdout=False, stderr=False: (
        b"" if stdout else b"FAILED tests/test_auth.py"
    )

    service = DockerSandboxService(docker_client=mock_docker_client)
    res = await service.run_test_in_sandbox(service_name="auth_service")

    assert res["status"] == "FAILED"
    assert res["exit_code"] == 1
    assert "FAILED tests/test_auth.py" in res["stderr"]


@pytest.mark.asyncio
async def test_run_test_in_sandbox_timeout(mock_docker_client):
    """Test timeout during test execution kills container and reports TIMEOUT."""
    container = mock_docker_client.containers.create.return_value
    container.wait.side_effect = Exception("Read timed out")

    service = DockerSandboxService(docker_client=mock_docker_client)
    res = await service.run_test_in_sandbox(
        service_name="auth_service", timeout_sec=1
    )

    assert res["status"] == "TIMEOUT"
    assert res["exit_code"] == 124
    container.kill.assert_called_once()


@pytest.mark.asyncio
async def test_run_test_in_sandbox_docker_error():
    """Verify service handles missing docker connection without crashing."""
    service = DockerSandboxService()
    # Force _get_client to raise exception
    service._get_client = MagicMock(side_effect=RuntimeError("Cannot connect to docker daemon"))

    res = await service.run_test_in_sandbox(service_name="auth_service")
    assert res["status"] == "FAILED"
    assert "Cannot connect to docker daemon" in res["stderr"]


@pytest.mark.asyncio
async def test_cleanup_sandbox_success(mock_docker_client):
    """Test container cleanup succeeds."""
    service = DockerSandboxService(docker_client=mock_docker_client)
    success = await service.cleanup_sandbox("c1234567890a")
    assert success is True


def test_create_sandbox_mcp_server_factory(mock_docker_client):
    """Test sandbox MCP server factory instantiation."""
    server = create_sandbox_mcp_server(docker_client=mock_docker_client)
    assert server is not None
