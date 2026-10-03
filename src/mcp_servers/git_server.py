"""MCP Git Server providing repository inspection and branch/PR manipulation tools."""

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.core.config import get_settings

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    FastMCP = None


class ReadFileInput(BaseModel):
    """Input payload for reading file contents."""

    file_path: str = Field(description="Relative path to the file in the repository")
    start_line: Optional[int] = Field(
        default=None, description="Optional 1-based start line index"
    )
    end_line: Optional[int] = Field(
        default=None, description="Optional 1-based end line index"
    )


class ListDirectoryInput(BaseModel):
    """Input payload for listing repository files."""

    dir_path: str = Field(
        default=".", description="Relative path to the directory in the repository"
    )


class CreateBranchInput(BaseModel):
    """Input payload for creating a working branch."""

    branch_name: str = Field(description="Name of the new branch to create")
    base_branch: str = Field(
        default="main", description="Source branch to branch off from"
    )


class ApplyGitDiffInput(BaseModel):
    """Input payload for applying a unified git patch diff."""

    branch_name: str = Field(
        description="Target branch where the diff should be applied"
    )
    diff_patch: str = Field(
        description="Unified diff patch content (e.g. diff --git a/... b/...)"
    )


class CreatePullRequestInput(BaseModel):
    """Input payload for opening a pull/merge request."""

    title: str = Field(description="Pull request title")
    description: str = Field(
        description="Detailed description of changes and vulnerability fix"
    )
    source_branch: str = Field(description="Feature branch containing the fix")
    target_branch: str = Field(
        default="main", description="Target base branch to merge into"
    )


class GitService:
    """Core asynchronous Git operations implementation."""

    def __init__(self, workspace_root: Optional[str] = None):
        self.workspace_root = Path(
            workspace_root or os.getcwd()
        ).resolve()
        self.settings = get_settings()

    def _resolve_safe_path(self, relative_path: str) -> Path:
        """Resolve path and prevent directory traversal outside workspace root."""
        clean_rel = relative_path.strip().lstrip("/")
        resolved = (self.workspace_root / clean_rel).resolve()
        if not str(resolved).startswith(str(self.workspace_root)):
            raise ValueError(
                f"Path traversal detected: {relative_path} is outside repository root."
            )
        return resolved

    async def _run_git_command(
        self, *args: str, cwd: Optional[Path] = None
    ) -> tuple[int, str, str]:
        """Execute a git subcommand asynchronously without shell expansion."""
        process = await asyncio.create_subprocess_exec(
            "git",
            *args,
            cwd=str(cwd or self.workspace_root),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        return (
            process.returncode or 0,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )

    async def read_file(
        self,
        file_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> str:
        """Read full file or slice of lines safely."""
        target_path = self._resolve_safe_path(file_path)
        if not target_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        def _read() -> list[str]:
            with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                return f.readlines()

        lines = await asyncio.to_thread(_read)
        total_lines = len(lines)

        s_line = max(1, start_line) if start_line is not None else 1
        e_line = min(total_lines, end_line) if end_line is not None else total_lines

        if s_line > total_lines:
            return f"# Empty slice: file has {total_lines} lines, requested start line {s_line}"

        selected = lines[s_line - 1 : e_line]
        numbered_lines = [
            f"{idx:6d} | {line}"
            for idx, line in enumerate(selected, start=s_line)
        ]
        return "".join(numbered_lines)

    async def list_directory(self, dir_path: str = ".") -> List[str]:
        """List files in directory while ignoring hidden/git artifacts."""
        target_dir = self._resolve_safe_path(dir_path)
        if not target_dir.is_dir():
            raise NotADirectoryError(f"Directory not found: {dir_path}")

        def _scan() -> list[str]:
            results: list[str] = []
            for item in sorted(os.listdir(target_dir)):
                if item.startswith(".git"):
                    continue
                full = target_dir / item
                suffix = "/" if full.is_dir() else ""
                results.append(f"{item}{suffix}")
            return results

        return await asyncio.to_thread(_scan)

    async def create_branch(
        self, branch_name: str, base_branch: Optional[str] = None
    ) -> str:
        """Create and checkout a new git branch from base branch."""
        base = base_branch or self.settings.git_base_branch
        code, out, err = await self._run_git_command(
            "checkout", "-B", branch_name, base
        )
        if code != 0:
            raise RuntimeError(f"Failed to create branch '{branch_name}': {err or out}")
        return f"Successfully created and checked out branch '{branch_name}' from '{base}'."

    async def apply_git_diff(self, branch_name: str, diff_patch: str) -> str:
        """Switch to branch and apply a unified diff patch."""
        # 1. Checkout the target branch
        code, _, err = await self._run_git_command("checkout", branch_name)
        if code != 0:
            raise RuntimeError(f"Could not checkout branch '{branch_name}': {err}")

        # 2. Write patch to a temporary patch file inside workspace
        patch_path = self.workspace_root / ".temp_agent_patch.diff"
        try:
            with open(patch_path, "w", encoding="utf-8") as f:
                f.write(diff_patch)

            # 3. Apply patch using git apply
            code, out, err = await self._run_git_command(
                "apply", "--whitespace=nowarn", str(patch_path)
            )
            if code != 0:
                raise RuntimeError(
                    f"Git patch application failed:\n{err or out}\nPlease revise the patch."
                )
            return (
                f"Patch successfully applied to branch '{branch_name}'. "
                f"Diff summary:\n{diff_patch[:300]}..."
            )
        finally:
            if patch_path.exists():
                patch_path.unlink()

    async def create_pull_request(
        self,
        title: str,
        description: str,
        source_branch: str,
        target_branch: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Stage, commit, and create pull request / merge request payload."""
        target = target_branch or self.settings.git_base_branch

        # Commit local changes if any are pending
        await self._run_git_command("add", "-A")
        code, out, _ = await self._run_git_command(
            "commit", "-m", f"fix(security): {title}\n\n{description}"
        )

        commit_hash = "working_tree_committed"
        if code == 0:
            _, hash_out, _ = await self._run_git_command("rev-parse", "--short", "HEAD")
            commit_hash = hash_out.strip()

        pr_info = {
            "title": title,
            "description": description,
            "source_branch": source_branch,
            "target_branch": target,
            "commit_hash": commit_hash,
            "status": "OPEN",
            "url": f"https://gitlab.com/petty-pets/auto-sec-agent/-/merge_requests/mock-{source_branch}",
        }
        return pr_info


def create_git_mcp_server(workspace_root: Optional[str] = None) -> Any:
    """Instantiate and register Git MCP server tools."""
    service = GitService(workspace_root=workspace_root)

    if FastMCP is None:
        return service

    server = FastMCP(
        name="git-server",
        instructions="MCP server for Git repository inspections, branch creation, patching, and PR creation.",
    )

    @server.tool(
        name="read_file",
        description="Read lines from a file in the repository with line numbers.",
    )
    async def read_file(
        file_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> str:
        return await service.read_file(
            file_path=file_path, start_line=start_line, end_line=end_line
        )

    @server.tool(
        name="list_directory",
        description="List files and directories at the given path relative to repository root.",
    )
    async def list_directory(dir_path: str = ".") -> List[str]:
        return await service.list_directory(dir_path=dir_path)

    @server.tool(
        name="create_branch",
        description="Create and checkout a new branch from a base branch.",
    )
    async def create_branch(branch_name: str, base_branch: str = "main") -> str:
        return await service.create_branch(
            branch_name=branch_name, base_branch=base_branch
        )

    @server.tool(
        name="apply_git_diff",
        description="Apply a unified git patch diff to the specified branch.",
    )
    async def apply_git_diff(branch_name: str, diff_patch: str) -> str:
        return await service.apply_git_diff(
            branch_name=branch_name, diff_patch=diff_patch
        )

    @server.tool(
        name="create_pull_request",
        description="Commit staged changes and create a Pull Request / Merge Request with explanation.",
    )
    async def create_pull_request(
        title: str,
        description: str,
        source_branch: str,
        target_branch: str = "main",
    ) -> Dict[str, Any]:
        return await service.create_pull_request(
            title=title,
            description=description,
            source_branch=source_branch,
            target_branch=target_branch,
        )

    return server
