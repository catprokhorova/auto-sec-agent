"""MCP Sandbox Runner Server executing test reproduction and patch validation in Docker containers."""

import asyncio
import logging
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from src.core.config import get_settings

try:
    import docker
    from docker.errors import DockerException, NotFound
except ImportError:  # pragma: no cover
    docker = None
    DockerException = Exception
    NotFound = Exception

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    FastMCP = None

logger = logging.getLogger(__name__)


class RunTestInSandboxInput(BaseModel):
    """Input payload for running tests inside an isolated Docker sandbox."""

    service_name: str = Field(
        description="Name of the target microservice (e.g. auth_service)"
    )
    patch_diff: str = Field(
        default="", description="Unified git diff to apply before running tests"
    )
    test_command: str = Field(
        default="pytest", description="Command to execute test suite (e.g. pytest tests/)"
    )
    image: Optional[str] = Field(
        default=None, description="Optional custom docker image name"
    )
    timeout_sec: Optional[int] = Field(
        default=None, description="Maximum execution timeout in seconds"
    )


class CleanupSandboxInput(BaseModel):
    """Input payload for cleaning up an ephemeral sandbox container."""

    container_id: str = Field(description="Docker container ID or name to terminate")


class SandboxTestResult(BaseModel):
    """Execution result returned from sandbox container."""

    exit_code: int = Field(description="Command return status code (0 for success)")
    stdout: str = Field(description="Standard output produced by test execution")
    stderr: str = Field(description="Standard error output produced by test execution")
    container_id: Optional[str] = Field(
        default=None, description="ID of container that ran tests"
    )
    duration_sec: float = Field(default=0.0, description="Total execution time in seconds")
    status: str = Field(
        description="Final execution status: 'PASSED', 'FAILED', or 'TIMEOUT'"
    )


class DockerSandboxService:
    """Service managing Docker container lifecycle and isolated test execution."""

    def __init__(self, docker_client: Optional[Any] = None):
        self.settings = get_settings()
        self._custom_client = docker_client

    def _get_client(self) -> Any:
        """Obtain connected Docker client or raise informative error."""
        if self._custom_client is not None:
            return self._custom_client

        if docker is None:
            raise RuntimeError("docker package is not installed.")

        try:
            return docker.DockerClient(base_url=self.settings.docker_host)
        except DockerException as exc:
            try:
                # Fallback to default local environment
                return docker.from_env()
            except DockerException:
                raise RuntimeError(
                    f"Unable to connect to Docker daemon at {self.settings.docker_host}: {exc}"
                )

    def _execute_in_container_sync(
        self,
        service_name: str,
        patch_diff: str,
        test_command: str,
        image_name: str,
        timeout: int,
    ) -> Dict[str, Any]:
        """Synchronous container execution logic intended for asyncio.to_thread."""
        client = self._get_client()
        container = None
        container_id = "unknown"

        # Build execution script that applies patch and executes test
        safe_patch = patch_diff.replace("'", "'\\''")
        shell_script = (
            "set -e\n"
            "cd /app || exit 1\n"
            f"if [ -n '{safe_patch}' ]; then\n"
            f"  cat << 'EOF' > /tmp/patch.diff\n{patch_diff}\nEOF\n"
            "  git apply --whitespace=nowarn /tmp/patch.diff || patch -p1 < /tmp/patch.diff\n"
            "fi\n"
            f"{test_command}\n"
        )

        try:
            container = client.containers.create(
                image=image_name,
                command=["/bin/sh", "-c", shell_script],
                labels={"app": "auto-sec-agent-sandbox", "service": service_name},
                network_disabled=False,
                mem_limit="512m",
                nano_cpus=1000000000,  # 1 CPU
                detach=True,
            )
            container_id = container.id[:12]
            container.start()

            # Wait with timeout
            try:
                wait_res = container.wait(timeout=timeout)
                exit_code = (
                    wait_res.get("StatusCode", 1)
                    if isinstance(wait_res, dict)
                    else getattr(wait_res, "StatusCode", 1)
                )
                stdout = container.logs(stdout=True, stderr=False).decode(
                    "utf-8", errors="replace"
                )
                stderr = container.logs(stdout=False, stderr=True).decode(
                    "utf-8", errors="replace"
                )
                status = "PASSED" if exit_code == 0 else "FAILED"
            except Exception as wait_exc:
                # Timeout or interruption
                container.kill()
                exit_code = 124
                stdout = ""
                stderr = f"Execution timed out after {timeout} seconds: {wait_exc}"
                status = "TIMEOUT"

            return {
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "container_id": container_id,
                "status": status,
            }

        finally:
            if container is not None:
                try:
                    container.remove(force=True, v=True)
                except Exception as clean_err:
                    logger.warning(
                        "Failed to remove container %s: %s", container_id, clean_err
                    )

    async def run_test_in_sandbox(
        self,
        service_name: str,
        patch_diff: str = "",
        test_command: str = "pytest",
        image: Optional[str] = None,
        timeout_sec: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Execute test suite asynchronously inside isolated Docker sandbox container."""
        image_name = image or self.settings.sandbox_default_image
        timeout = timeout_sec or self.settings.sandbox_exec_timeout_sec

        loop = asyncio.get_running_loop()
        start_time = loop.time()

        try:
            raw_res = await asyncio.to_thread(
                self._execute_in_container_sync,
                service_name,
                patch_diff,
                test_command,
                image_name,
                timeout,
            )
        except Exception as exc:
            # Handle docker connection or setup failure gracefully
            raw_res = {
                "exit_code": 1,
                "stdout": "",
                "stderr": f"Sandbox runner error: {exc}",
                "container_id": None,
                "status": "FAILED",
            }

        raw_res["duration_sec"] = round(loop.time() - start_time, 2)
        # Validate against Pydantic schema
        validated = SandboxTestResult(**raw_res)
        return validated.model_dump()

    async def cleanup_sandbox(self, container_id: str) -> bool:
        """Forcefully remove a specific container."""
        client = self._get_client()

        def _remove() -> bool:
            try:
                container = client.containers.get(container_id)
                container.remove(force=True, v=True)
                return True
            except NotFound:
                return True
            except Exception as exc:
                logger.error("Error removing container %s: %s", container_id, exc)
                return False

        return await asyncio.to_thread(_remove)


def create_sandbox_mcp_server(docker_client: Optional[Any] = None) -> Any:
    """Instantiate and register Docker Sandbox MCP server tools."""
    service = DockerSandboxService(docker_client=docker_client)

    if FastMCP is None:
        return service

    server = FastMCP(
        name="sandbox-server",
        instructions="MCP server for executing tests and patches inside isolated Docker sandboxes.",
    )

    @server.tool(
        name="run_test_in_sandbox",
        description="Runs test suite for a microservice inside an isolated docker container after applying patch.",
    )
    async def run_test_in_sandbox(
        service_name: str,
        patch_diff: str = "",
        test_command: str = "pytest",
        image: Optional[str] = None,
        timeout_sec: Optional[int] = None,
    ) -> Dict[str, Any]:
        return await service.run_test_in_sandbox(
            service_name=service_name,
            patch_diff=patch_diff,
            test_command=test_command,
            image=image,
            timeout_sec=timeout_sec,
        )

    @server.tool(
        name="cleanup_sandbox",
        description="Terminates and removes an ephemeral sandbox container by ID.",
    )
    async def cleanup_sandbox(container_id: str) -> bool:
        return await service.cleanup_sandbox(container_id=container_id)

    return server
