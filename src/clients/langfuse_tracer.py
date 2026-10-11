"""Observability and evaluation tracer with Langfuse integration."""

import logging
import uuid
from typing import Any

from pydantic import BaseModel, Field

from src.core.config import Settings, get_settings

logger = logging.getLogger(__name__)

# Standard AWS Bedrock pricing per 1M tokens (as of Claude 3.5 models)
CLAUDE_35_SONNET_INPUT_PER_1M = 3.00
CLAUDE_35_SONNET_OUTPUT_PER_1M = 15.00
CLAUDE_35_HAIKU_INPUT_PER_1M = 0.80
CLAUDE_35_HAIKU_OUTPUT_PER_1M = 4.00


class ToolCallRecord(BaseModel):
    """Execution record for an MCP tool call."""

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    success: bool
    is_hallucination: bool = False
    error_message: str | None = None


class TraceRecord(BaseModel):
    """In-memory trace record tracking agent trajectory, costs, and resilience events."""

    trace_id: str
    name: str = "security-agent-run"
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    trajectory: list[str] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    circuit_breaker_triggered: bool = False
    circuit_breaker_reason: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    total_cost_usd: float = 0.0


class LangfuseTracer:
    """Resilient tracer integrating Langfuse observability with fallback in-memory metrics."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._traces: dict[str, TraceRecord] = {}
        self._client: Any = None
        self._callback_handler: Any = None

        if self.settings.langfuse_enabled:
            self._init_langfuse()

    def _init_langfuse(self) -> None:
        """Initialize Langfuse client and callback handler if configured."""
        try:
            from langfuse import Langfuse

            self._client = Langfuse(
                public_key=self.settings.langfuse_public_key,
                secret_key=self.settings.langfuse_secret_key,
                host=self.settings.langfuse_host,
            )
            logger.info("Langfuse client initialized successfully.")
        except Exception as exc:
            logger.warning(
                "Failed to initialize Langfuse client: %s. Using in-memory fallback.",
                exc,
            )
            self._client = None

        # Attempt to load LangChain/LangGraph callback handler
        try:
            try:
                from langfuse.langchain import CallbackHandler  # type: ignore

                self._callback_handler = CallbackHandler(
                    public_key=self.settings.langfuse_public_key,
                    secret_key=self.settings.langfuse_secret_key,
                    host=self.settings.langfuse_host,
                )
            except ImportError:
                from langfuse.callback import CallbackHandler  # type: ignore

                self._callback_handler = CallbackHandler(
                    public_key=self.settings.langfuse_public_key,
                    secret_key=self.settings.langfuse_secret_key,
                    host=self.settings.langfuse_host,
                )
        except Exception as exc:
            logger.debug("Langfuse CallbackHandler not available: %s", exc)
            self._callback_handler = None

    def calculate_cost(
        self, model: str, input_tokens: int, output_tokens: int
    ) -> float:
        """Calculate token cost in USD based on AWS Bedrock Claude model pricing."""
        model_lower = model.lower()
        if "haiku" in model_lower:
            input_rate = CLAUDE_35_HAIKU_INPUT_PER_1M / 1_000_000
            output_rate = CLAUDE_35_HAIKU_OUTPUT_PER_1M / 1_000_000
        else:
            # Default to Sonnet pricing
            input_rate = CLAUDE_35_SONNET_INPUT_PER_1M / 1_000_000
            output_rate = CLAUDE_35_SONNET_OUTPUT_PER_1M / 1_000_000

        return (input_tokens * input_rate) + (output_tokens * output_rate)

    def start_trace(
        self,
        name: str = "security-agent-run",
        metadata: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        trace_id: str | None = None,
    ) -> str:
        """Begin a new execution trace, returning unique trace_id."""
        tid = trace_id or f"trace_{uuid.uuid4().hex[:12]}"
        record = TraceRecord(
            trace_id=tid,
            name=name,
            metadata=metadata or {},
            tags=tags or ["security-agent"],
        )
        self._traces[tid] = record

        if self._client:
            try:
                self._client.trace(
                    id=tid,
                    name=name,
                    metadata=metadata,
                    tags=tags,
                )
            except Exception as exc:
                logger.warning("Langfuse start_trace failed: %s", exc)

        return tid

    def log_node_execution(
        self,
        trace_id: str,
        node_name: str,
        inputs: dict[str, Any] | None = None,
        outputs: dict[str, Any] | None = None,
        latency_ms: float = 0.0,
    ) -> None:
        """Record step in the agent trajectory."""
        if trace_id in self._traces:
            self._traces[trace_id].trajectory.append(node_name)

        if self._client:
            try:
                self._client.span(
                    trace_id=trace_id,
                    name=f"node_{node_name}",
                    input=inputs,
                    output=outputs,
                    metadata={"latency_ms": latency_ms},
                )
            except Exception as exc:
                logger.warning("Langfuse log_node_execution failed: %s", exc)

    def log_tool_call(
        self,
        trace_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        success: bool,
        is_hallucination: bool = False,
        error_message: str | None = None,
    ) -> None:
        """Record tool call outcome for Tool-Calling Accuracy calculations."""
        record = ToolCallRecord(
            tool_name=tool_name,
            arguments=arguments,
            success=success,
            is_hallucination=is_hallucination,
            error_message=error_message,
        )

        if trace_id in self._traces:
            self._traces[trace_id].tool_calls.append(record)

        if self._client:
            try:
                self._client.event(
                    trace_id=trace_id,
                    name=f"tool_{tool_name}",
                    metadata={
                        "success": success,
                        "is_hallucination": is_hallucination,
                        "error_message": error_message,
                    },
                )
            except Exception as exc:
                logger.warning("Langfuse log_tool_call failed: %s", exc)

    def log_circuit_breaker(
        self,
        trace_id: str,
        reason: str,
        loop_counter: int,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record a circuit breaker escalation event."""
        if trace_id in self._traces:
            self._traces[trace_id].circuit_breaker_triggered = True
            self._traces[trace_id].circuit_breaker_reason = reason

        if self._client:
            try:
                meta = metadata or {}
                meta.update({"loop_counter": loop_counter, "reason": reason})
                self._client.score(
                    trace_id=trace_id,
                    name="circuit_breaker_tripped",
                    value=1.0,
                    comment=reason,
                )
                self._client.event(
                    trace_id=trace_id,
                    name="circuit_breaker_escalation",
                    metadata=meta,
                )
            except Exception as exc:
                logger.warning("Langfuse log_circuit_breaker failed: %s", exc)

    def record_token_usage(
        self,
        trace_id: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> None:
        """Aggregate token counts and compute Bedrock costs."""
        cost = self.calculate_cost(model, input_tokens, output_tokens)
        if trace_id in self._traces:
            trace = self._traces[trace_id]
            trace.input_tokens += input_tokens
            trace.output_tokens += output_tokens
            trace.total_cost_usd += cost

        if self._client:
            try:
                self._client.generation(
                    trace_id=trace_id,
                    name=f"generation_{model}",
                    model=model,
                    usage={
                        "input": input_tokens,
                        "output": output_tokens,
                        "total": input_tokens + output_tokens,
                    },
                    calculated_cost=cost,
                )
            except Exception as exc:
                logger.warning("Langfuse record_token_usage failed: %s", exc)

    def get_metrics(self, trace_id: str) -> dict[str, Any]:
        """Compute Trajectory Consistency, Tool-Calling Accuracy, and Cost per Resolution."""
        trace = self._traces.get(trace_id)
        if not trace:
            return {
                "trace_id": trace_id,
                "error": "Trace not found",
            }

        trajectory = trace.trajectory
        step_count = len(trajectory)
        is_optimal = step_count == 5 and (
            trajectory[-1] == "create_pr" if trajectory else False
        )

        total_tool_calls = len(trace.tool_calls)
        successful_calls = sum(1 for c in trace.tool_calls if c.success)
        hallucinated_calls = sum(1 for c in trace.tool_calls if c.is_hallucination)

        # Tool-calling accuracy: 1.0 if no calls or hallucinations, else successful / total
        if total_tool_calls == 0:
            tool_accuracy = 1.0
        else:
            tool_accuracy = successful_calls / total_tool_calls

        # Trajectory consistency score: 1.0 if optimal (5 steps), degrades if looping
        if is_optimal:
            consistency_score = 1.0
        elif "create_pr" in trajectory:
            # Succeeded via self-correction retry
            consistency_score = max(0.5, 1.0 - 0.15 * (step_count - 5))
        else:
            # Escalated
            consistency_score = 0.0

        return {
            "trace_id": trace.trace_id,
            "trajectory_steps": trajectory,
            "step_count": step_count,
            "is_optimal_trajectory": is_optimal,
            "trajectory_consistency_score": round(consistency_score, 2),
            "total_tool_calls": total_tool_calls,
            "successful_tool_calls": successful_calls,
            "hallucinated_tool_calls": hallucinated_calls,
            "tool_calling_accuracy": round(tool_accuracy, 2),
            "circuit_breaker_triggered": trace.circuit_breaker_triggered,
            "circuit_breaker_reason": trace.circuit_breaker_reason,
            "total_input_tokens": trace.input_tokens,
            "total_output_tokens": trace.output_tokens,
            "total_cost_usd": round(trace.total_cost_usd, 6),
        }

    def get_langchain_callback(self) -> Any:
        """Return initialized Langfuse CallbackHandler for LangGraph if available."""
        return self._callback_handler

    def flush(self) -> None:
        """Safely flush pending Langfuse events to remote host."""
        if self._client:
            try:
                self._client.flush()
            except Exception as exc:
                logger.warning("Langfuse flush failed: %s", exc)
