"""Resilient MCP Client Gateway with Tool-Calling Validation Interceptor."""

import inspect
import logging
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from src.mcp_servers.git_server import (
    ApplyGitDiffInput,
    CreateBranchInput,
    CreatePullRequestInput,
    GitService,
    ListDirectoryInput,
    ReadFileInput,
)
from src.mcp_servers.knowledge_server import (
    ImpactRadiusInput,
    KnowledgeGraphService,
    SemanticSearchInput,
    ServiceDependenciesInput,
)
from src.mcp_servers.sandbox_server import (
    CleanupSandboxInput,
    DockerSandboxService,
    RunTestInSandboxInput,
)

logger = logging.getLogger(__name__)


class StrictToolInput(BaseModel):
    """Base class for tool inputs that forbids extra/hallucinated arguments."""

    model_config = ConfigDict(extra="forbid")


# Define strict models with extra="forbid" to intercept hallucinations
class StrictReadFileInput(ReadFileInput, StrictToolInput):
    pass


class StrictListDirectoryInput(ListDirectoryInput, StrictToolInput):
    pass


class StrictCreateBranchInput(CreateBranchInput, StrictToolInput):
    pass


class StrictApplyGitDiffInput(ApplyGitDiffInput, StrictToolInput):
    pass


class StrictCreatePullRequestInput(CreatePullRequestInput, StrictToolInput):
    pass


class StrictRunTestInSandboxInput(RunTestInSandboxInput, StrictToolInput):
    pass


class StrictCleanupSandboxInput(CleanupSandboxInput, StrictToolInput):
    pass


class StrictServiceDependenciesInput(ServiceDependenciesInput, StrictToolInput):
    pass


class StrictImpactRadiusInput(ImpactRadiusInput, StrictToolInput):
    pass


class StrictSemanticSearchInput(SemanticSearchInput, StrictToolInput):
    pass


class ToolExecutionResult(BaseModel):
    """Result of an MCP tool invocation with resilience feedback."""

    tool_name: str = Field(description="Name of the tool called")
    arguments: dict[str, Any] = Field(
        default_factory=dict, description="Arguments passed to the tool"
    )
    success: bool = Field(description="Whether the tool executed successfully")
    output: Any = Field(default=None, description="Output returned on success")
    error_message: str | None = Field(
        default=None, description="Error message if execution failed"
    )
    guidance_for_model: str | None = Field(
        default=None,
        description="Structured recovery guidance provided to LLM for self-correction",
    )
    is_hallucination: bool = Field(
        default=False,
        description="True if error was caused by tool or argument hallucination",
    )


class ToolDefinition(BaseModel):
    """Registered tool metadata and validation specification."""

    name: str
    description: str
    input_model: type[BaseModel]
    handler: Any  # Callable handler

    model_config = ConfigDict(arbitrary_types_allowed=True)


class MCPGateway:
    """Resilient gateway that intercepts tool hallucinations and dispatches calls safely."""

    def __init__(
        self,
        git_service: GitService | None = None,
        sandbox_service: DockerSandboxService | None = None,
        knowledge_service: KnowledgeGraphService | None = None,
    ):
        self.git_service = git_service or GitService()
        self.sandbox_service = sandbox_service or DockerSandboxService()
        self.knowledge_service = knowledge_service or KnowledgeGraphService()

        self._tools: dict[str, ToolDefinition] = {}
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        """Register default tools for Git, Sandbox, and Knowledge Graph."""
        # Git Tools
        self.register_tool(
            name="read_file",
            input_model=StrictReadFileInput,
            handler=self.git_service.read_file,
            description="Read file contents with optional start_line and end_line bounds.",
        )
        self.register_tool(
            name="list_directory",
            input_model=StrictListDirectoryInput,
            handler=self.git_service.list_directory,
            description="List directory files and folders.",
        )
        self.register_tool(
            name="create_branch",
            input_model=StrictCreateBranchInput,
            handler=self.git_service.create_branch,
            description="Create and switch to a new branch off base branch.",
        )
        self.register_tool(
            name="apply_git_diff",
            input_model=StrictApplyGitDiffInput,
            handler=self.git_service.apply_git_diff,
            description="Apply a unified git diff patch to the target branch.",
        )
        self.register_tool(
            name="create_pull_request",
            input_model=StrictCreatePullRequestInput,
            handler=self.git_service.create_pull_request,
            description="Commit changes and open a pull/merge request.",
        )

        # Sandbox Runner Tools
        self.register_tool(
            name="run_test_in_sandbox",
            input_model=StrictRunTestInSandboxInput,
            handler=self.sandbox_service.run_test_in_sandbox,
            description="Execute test suite inside an isolated Docker sandbox after applying patch.",
        )
        self.register_tool(
            name="cleanup_sandbox",
            input_model=StrictCleanupSandboxInput,
            handler=self.sandbox_service.cleanup_sandbox,
            description="Clean up ephemeral Docker container.",
        )

        # Knowledge Graph & RAG Tools
        self.register_tool(
            name="get_service_dependencies",
            input_model=StrictServiceDependenciesInput,
            handler=self.knowledge_service.get_service_dependencies,
            description="Retrieve microservice dependencies from Neo4j knowledge graph.",
        )
        self.register_tool(
            name="get_impact_radius",
            input_model=StrictImpactRadiusInput,
            handler=self.knowledge_service.get_impact_radius,
            description="Get impacted files, microservices, and suggested test suites for a file.",
        )
        self.register_tool(
            name="semantic_code_search",
            input_model=StrictSemanticSearchInput,
            handler=self.knowledge_service.semantic_code_search,
            description="Perform semantic search for security docs, CVE fixes, and code examples.",
        )

    def register_tool(
        self,
        name: str,
        input_model: type[BaseModel],
        handler: Callable[..., Any],
        description: str = "",
    ) -> None:
        """Register a tool with its validation schema and handler."""
        self._tools[name] = ToolDefinition(
            name=name,
            description=description,
            input_model=input_model,
            handler=handler,
        )

    def get_available_tool_names(self) -> list[str]:
        """Return list of all registered tool names."""
        return sorted(self._tools.keys())

    def get_tool_signatures(self) -> list[dict[str, Any]]:
        """Return Claude/Bedrock-compatible JSON Schema tool specifications."""
        signatures: list[dict[str, Any]] = []
        for name, tool in self._tools.items():
            schema = tool.input_model.model_json_schema()
            signatures.append(
                {
                    "toolSpec": {
                        "name": name,
                        "description": tool.description,
                        "inputSchema": {
                            "json": schema,
                        },
                    }
                }
            )
        return signatures

    def _find_similar_tool(self, name: str) -> str | None:
        """Suggest closest tool name if caller made a typo or hallucination."""
        name_lower = name.lower()
        for valid in self._tools:
            if name_lower in valid or valid in name_lower:
                return valid
        return None

    async def execute_tool(
        self, tool_name: str, arguments: dict[str, Any] | None = None
    ) -> ToolExecutionResult:
        """Intercept validation/argument hallucinations before execution.

        Returns structured guidance to the model upon failure instead of crashing.
        """
        args = arguments or {}

        # 1. Intercept Tool Name Hallucination
        if tool_name not in self._tools:
            available = ", ".join(self.get_available_tool_names())
            suggestion = self._find_similar_tool(tool_name)
            guidance = (
                f"Error: Tool '{tool_name}' does not exist. "
                + (f"Did you mean '{suggestion}'? " if suggestion else "")
                + f"Available tools are: [{available}]. Please correct your tool call."
            )
            logger.warning("Tool hallucination detected: %s", tool_name)
            return ToolExecutionResult(
                tool_name=tool_name,
                arguments=args,
                success=False,
                error_message=f"Tool '{tool_name}' not found.",
                guidance_for_model=guidance,
                is_hallucination=True,
            )

        tool = self._tools[tool_name]

        # 2. Intercept Parameter Hallucination via strict Pydantic model
        try:
            validated_input = tool.input_model(**args)
        except ValidationError as err:
            valid_fields = list(tool.input_model.model_fields.keys())
            hallucinated_args: list[str] = []
            for e in err.errors():
                if e.get("type") == "extra_forbidden":
                    loc = e.get("loc", ())
                    if loc:
                        hallucinated_args.append(str(loc[0]))

            guidance = f"Error: Tool '{tool_name}' validation failed: {err.error_count()} issue(s). "
            if hallucinated_args:
                guidance += (
                    f"Unexpected / hallucinated parameter(s): {hallucinated_args}. "
                    f"Valid arguments for '{tool_name}' are: {valid_fields}. "
                    f"Please remove unsupported parameters and retry."
                )
            else:
                guidance += (
                    f"Valid arguments are: {valid_fields}. Detail: {err.errors()}"
                )

            logger.warning("Parameter hallucination on '%s': %s", tool_name, err)
            return ToolExecutionResult(
                tool_name=tool_name,
                arguments=args,
                success=False,
                error_message=str(err),
                guidance_for_model=guidance,
                is_hallucination=True,
            )

        # 3. Safe Execution in Try/Except
        try:
            dumped_kwargs = validated_input.model_dump()
            handler = tool.handler

            if inspect.iscoroutinefunction(handler):
                output = await handler(**dumped_kwargs)
            else:
                output = handler(**dumped_kwargs)

            return ToolExecutionResult(
                tool_name=tool_name,
                arguments=dumped_kwargs,
                success=True,
                output=output,
                guidance_for_model=None,
                is_hallucination=False,
            )
        except Exception as exc:
            logger.error("Error executing tool '%s': %s", tool_name, exc, exc_info=True)
            guidance = (
                f"Error executing '{tool_name}': {type(exc).__name__}: {exc}. "
                f"Please check your input values and try an alternative approach."
            )
            return ToolExecutionResult(
                tool_name=tool_name,
                arguments=args,
                success=False,
                error_message=str(exc),
                guidance_for_model=guidance,
                is_hallucination=False,
            )
