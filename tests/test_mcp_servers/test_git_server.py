"""Unit tests for MCP Git Server and GitService."""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock

from src.mcp_servers.git_server import GitService, create_git_mcp_server


@pytest.fixture
def temp_workspace(tmp_path: Path) -> Path:
    """Create a temporary workspace directory populated with sample files."""
    code_dir = tmp_path / "services" / "auth"
    code_dir.mkdir(parents=True)
    sample_file = code_dir / "service.py"
    sample_file.write_text(
        "def login(user, password):\n"
        "    # vulnerable query\n"
        "    query = f'SELECT * FROM users WHERE user={user}'\n"
        "    return execute(query)\n"
    )
    return tmp_path


@pytest.mark.asyncio
async def test_read_file_success(temp_workspace: Path):
    """Test reading lines from a valid file with slice limits."""
    service = GitService(workspace_root=str(temp_workspace))
    content = await service.read_file("services/auth/service.py", start_line=2, end_line=3)

    assert "vulnerable query" in content
    assert "2 | " in content
    assert "3 | " in content
    assert "def login" not in content


@pytest.mark.asyncio
async def test_read_file_not_found(temp_workspace: Path):
    """Test reading a non-existent file raises FileNotFoundError."""
    service = GitService(workspace_root=str(temp_workspace))
    with pytest.raises(FileNotFoundError):
        await service.read_file("services/non_existent.py")


@pytest.mark.asyncio
async def test_path_traversal_prevention(temp_workspace: Path):
    """Verify directory traversal attempts raise ValueError."""
    service = GitService(workspace_root=str(temp_workspace))
    with pytest.raises(ValueError, match="Path traversal detected"):
        await service.read_file("../../etc/passwd")


@pytest.mark.asyncio
async def test_list_directory(temp_workspace: Path):
    """Test listing directory contents."""
    service = GitService(workspace_root=str(temp_workspace))
    items = await service.list_directory("services/auth")
    assert "service.py" in items


@pytest.mark.asyncio
async def test_create_branch_success(temp_workspace: Path, monkeypatch):
    """Test creating a new branch calls git checkout -B."""
    service = GitService(workspace_root=str(temp_workspace))
    mock_run = AsyncMock(return_value=(0, "Switched to a new branch 'fix-cve'", ""))
    monkeypatch.setattr(service, "_run_git_command", mock_run)

    result = await service.create_branch("fix-cve", "main")
    assert "Successfully created and checked out branch 'fix-cve'" in result
    mock_run.assert_called_once_with("checkout", "-B", "fix-cve", "main")


@pytest.mark.asyncio
async def test_create_branch_failure(temp_workspace: Path, monkeypatch):
    """Test git checkout failure raises RuntimeError."""
    service = GitService(workspace_root=str(temp_workspace))
    mock_run = AsyncMock(return_value=(1, "", "fatal: git error"))
    monkeypatch.setattr(service, "_run_git_command", mock_run)

    with pytest.raises(RuntimeError, match="Failed to create branch"):
        await service.create_branch("fix-cve", "main")


@pytest.mark.asyncio
async def test_apply_git_diff_success(temp_workspace: Path, monkeypatch):
    """Test applying a valid diff patch to a branch."""
    service = GitService(workspace_root=str(temp_workspace))
    mock_run = AsyncMock()
    mock_run.side_effect = [
        (0, "Switched to branch", ""),  # checkout
        (0, "Applied patch", ""),       # apply
    ]
    monkeypatch.setattr(service, "_run_git_command", mock_run)

    diff = "--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-old\n+new\n"
    result = await service.apply_git_diff("fix-cve", diff)
    assert "Patch successfully applied" in result


@pytest.mark.asyncio
async def test_create_pull_request(temp_workspace: Path, monkeypatch):
    """Test creating a pull request structure."""
    service = GitService(workspace_root=str(temp_workspace))
    mock_run = AsyncMock()
    mock_run.side_effect = [
        (0, "staged", ""),        # add -A
        (0, "committed", ""),     # commit
        (0, "abc1234\n", ""),     # rev-parse
    ]
    monkeypatch.setattr(service, "_run_git_command", mock_run)

    pr = await service.create_pull_request(
        title="Fix SQLi in auth service",
        description="Parameterized query to prevent injection",
        source_branch="fix-sqli",
        target_branch="main",
    )
    assert pr["title"] == "Fix SQLi in auth service"
    assert pr["source_branch"] == "fix-sqli"
    assert pr["status"] == "OPEN"
    assert "abc1234" in pr["commit_hash"]


def test_create_git_mcp_server_factory(temp_workspace: Path):
    """Test MCP git server factory instantiation."""
    server = create_git_mcp_server(workspace_root=str(temp_workspace))
    assert server is not None
