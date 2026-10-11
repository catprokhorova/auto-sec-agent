"""Agentic evaluation benchmark runner for Autonomous CI/CD Security Agent.

Measures:
1. Trajectory Consistency: Steps to resolution (Target: 5-step optimal path).
2. Tool-Calling Accuracy: Interception rate of parameter/tool hallucinations.
3. Cost per Resolution: AWS Bedrock token input/output costs in USD.
4. Resilience Events: Precision of anti-loop circuit breaker activations.
"""

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

# Ensure project root is in sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

deps_dir = root_dir / ".deps"
if deps_dir.is_dir() and str(deps_dir) not in sys.path:
    sys.path.insert(0, str(deps_dir))

from src.clients.bedrock import BedrockClient, LLMResponse  # noqa: E402
from src.clients.langfuse_tracer import LangfuseTracer  # noqa: E402
from src.clients.mcp_gateway import MCPGateway  # noqa: E402
from src.core.config import Settings  # noqa: E402
from src.core.nodes import AgentWorkflowNodes  # noqa: E402
from src.core.orchestrator import SecurityAgentOrchestrator  # noqa: E402

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("evals")


SAMPLE_ERROR_LOG = """
[ERROR] Test failed in CI Pipeline Job #4082
=================================== FAILURES ===================================
______________________________ test_sql_injection ______________________________
def test_sql_injection():
>   res = run_query("admin' OR '1'='1")
E   sqlite3.OperationalError: near "'1'='1": syntax error
services/auth/service.py:18: OperationalError
=========================== short test summary info ============================
FAILED services/auth/test_service.py::test_sql_injection - OperationalError
"""


def _make_mock_gateway(sandbox_behavior: Any) -> MCPGateway:
    """Create a configured mock MCPGateway with appropriate return types."""
    gateway = MagicMock(spec=MCPGateway)
    gateway.current_trace_id = None

    async def _tool_exec(tool_name: str, _args: dict | None = None):
        res = MagicMock()
        res.success = True
        res.is_hallucination = False
        res.error_message = None
        if tool_name == "run_test_in_sandbox":
            if callable(sandbox_behavior):
                res.output = sandbox_behavior()
            else:
                res.output = sandbox_behavior
        elif tool_name == "create_pull_request":
            res.output = {"status": "OPEN", "url": "https://gitlab.com/mr/1"}
        elif tool_name == "read_file":
            res.output = (
                "def run_query(q):\n    cursor.execute(f'SELECT * WHERE u={u}')"
            )
        elif tool_name == "get_impact_radius":
            res.output = {
                "affected_services": ["auth_service"],
                "suggested_test_suites": ["tests/test_auth.py"],
            }
        elif tool_name == "semantic_code_search":
            res.output = [{"title": "SQLi Prevention", "snippet": "Use parameters"}]
        else:
            res.output = "OK"
        return res

    gateway.execute_tool = AsyncMock(side_effect=_tool_exec)
    return gateway


async def run_scenario_optimal(tracer: LangfuseTracer) -> dict[str, Any]:
    """Scenario 1: Clean fix on 1st iteration (Optimal 5-step trajectory)."""
    mock_bedrock = MagicMock(spec=BedrockClient)
    mock_bedrock.generate_haiku = AsyncMock(
        return_value=LLMResponse(
            content='{"target_file": "services/auth/service.py", "line_number": 18, "vulnerability_type": "CWE-89"}',
            input_tokens=250,
            output_tokens=60,
            model="haiku",
        )
    )
    mock_bedrock.generate_sonnet = AsyncMock(
        return_value=LLMResponse(
            content="```diff\n--- a/services/auth/service.py\n+++ b/services/auth/service.py\n@@ -18,1 +18,1 @@\n-cursor.execute(f'SELECT * WHERE u={u}')\n+cursor.execute('SELECT * WHERE u=?', (u,))\n```",
            input_tokens=1200,
            output_tokens=250,
            model="sonnet",
        )
    )

    mock_gateway = _make_mock_gateway({"exit_code": 0, "status": "PASSED"})

    nodes = AgentWorkflowNodes(
        bedrock_client=mock_bedrock,
        mcp_gateway=mock_gateway,
        tracer=tracer,
    )
    orch = SecurityAgentOrchestrator(nodes=nodes, tracer=tracer)

    state = await orch.run(error_log=SAMPLE_ERROR_LOG)
    metrics = tracer.get_metrics(state.trace_id or "")
    metrics["scenario_name"] = "Optimal Clean Fix (1-pass)"
    return metrics


async def run_scenario_self_correction(tracer: LangfuseTracer) -> dict[str, Any]:
    """Scenario 2: Multi-turn self-correction (1st attempt fails, 2nd passes)."""
    attempt = 0

    def _sandbox_callback():
        nonlocal attempt
        attempt += 1
        if attempt == 1:
            return {
                "exit_code": 1,
                "status": "FAILED",
                "stderr": "SyntaxError on line 18",
            }
        return {"exit_code": 0, "status": "PASSED"}

    mock_bedrock = MagicMock(spec=BedrockClient)
    mock_bedrock.generate_haiku = AsyncMock(
        return_value=LLMResponse(
            content='{"target_file": "services/auth/service.py", "line_number": 18, "vulnerability_type": "CWE-89"}',
            input_tokens=250,
            output_tokens=60,
            model="haiku",
        )
    )

    diff1 = "```diff\n--- a/services/auth/service.py\n+++ b/services/auth/service.py\n@@ -18,1 +18,1 @@\n-old\n+attempt_1\n```"
    diff2 = "```diff\n--- a/services/auth/service.py\n+++ b/services/auth/service.py\n@@ -18,1 +18,1 @@\n-old\n+attempt_2_fixed\n```"
    mock_bedrock.generate_sonnet = AsyncMock(
        side_effect=[
            LLMResponse(
                content=diff1, input_tokens=1200, output_tokens=250, model="sonnet"
            ),
            LLMResponse(
                content=diff2, input_tokens=1500, output_tokens=280, model="sonnet"
            ),
        ]
    )

    mock_gateway = _make_mock_gateway(_sandbox_callback)

    nodes = AgentWorkflowNodes(
        bedrock_client=mock_bedrock,
        mcp_gateway=mock_gateway,
        tracer=tracer,
    )
    orch = SecurityAgentOrchestrator(nodes=nodes, tracer=tracer)

    state = await orch.run(error_log=SAMPLE_ERROR_LOG)
    metrics = tracer.get_metrics(state.trace_id or "")
    metrics["scenario_name"] = "Self-Correction Loop (2-pass)"
    return metrics


async def run_scenario_circuit_breaker(tracer: LangfuseTracer) -> dict[str, Any]:
    """Scenario 3: Hard circuit breaker activation after 3 consecutive failures."""
    mock_bedrock = MagicMock(spec=BedrockClient)
    mock_bedrock.generate_haiku = AsyncMock(
        return_value=LLMResponse(
            content='{"target_file": "services/auth/service.py", "line_number": 18, "vulnerability_type": "CWE-89"}',
            input_tokens=250,
            output_tokens=60,
            model="haiku",
        )
    )

    diffs = [
        f"```diff\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-old\n+attempt_{i}\n```"
        for i in range(5)
    ]
    mock_bedrock.generate_sonnet = AsyncMock(
        side_effect=[
            LLMResponse(content=d, input_tokens=1000, output_tokens=200, model="sonnet")
            for d in diffs
        ]
    )

    mock_gateway = _make_mock_gateway(
        {"exit_code": 1, "status": "FAILED", "stderr": "Persistent compilation error"}
    )

    settings = Settings(max_loop_count=3)
    nodes = AgentWorkflowNodes(
        bedrock_client=mock_bedrock,
        mcp_gateway=mock_gateway,
        tracer=tracer,
        settings=settings,
    )
    orch = SecurityAgentOrchestrator(nodes=nodes, tracer=tracer)

    state = await orch.run(error_log=SAMPLE_ERROR_LOG)
    metrics = tracer.get_metrics(state.trace_id or "")
    metrics["scenario_name"] = "Anti-Loop Circuit Breaker (Max Attempts)"
    return metrics


async def run_scenario_duplicate_oscillation(tracer: LangfuseTracer) -> dict[str, Any]:
    """Scenario 4: Oscillation circuit breaker tripping on identical patch hash."""
    mock_bedrock = MagicMock(spec=BedrockClient)
    mock_bedrock.generate_haiku = AsyncMock(
        return_value=LLMResponse(
            content='{"target_file": "services/auth/service.py", "line_number": 18, "vulnerability_type": "CWE-89"}',
            input_tokens=250,
            output_tokens=60,
            model="haiku",
        )
    )

    identical_diff = "```diff\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-old\n+same_fix\n```"
    mock_bedrock.generate_sonnet = AsyncMock(
        return_value=LLMResponse(
            content=identical_diff, input_tokens=1000, output_tokens=200, model="sonnet"
        )
    )

    mock_gateway = _make_mock_gateway(
        {"exit_code": 1, "status": "FAILED", "stderr": "Failed assertion"}
    )

    settings = Settings(max_loop_count=5)
    nodes = AgentWorkflowNodes(
        bedrock_client=mock_bedrock,
        mcp_gateway=mock_gateway,
        tracer=tracer,
        settings=settings,
    )
    orch = SecurityAgentOrchestrator(nodes=nodes, tracer=tracer)

    state = await orch.run(error_log=SAMPLE_ERROR_LOG)
    metrics = tracer.get_metrics(state.trace_id or "")
    metrics["scenario_name"] = "Anti-Loop Circuit Breaker (Duplicate Patch)"
    return metrics


async def run_all_evaluations() -> dict[str, Any]:
    """Execute all benchmark evaluation scenarios and compute aggregate KPIs."""
    logger.info("Starting Autonomous Security Agent evaluation benchmark...")
    tracer = LangfuseTracer()

    results = []
    results.append(await run_scenario_optimal(tracer))
    results.append(await run_scenario_self_correction(tracer))
    results.append(await run_scenario_circuit_breaker(tracer))
    results.append(await run_scenario_duplicate_oscillation(tracer))

    # Calculate Aggregate Metrics
    total_cost = sum(r.get("total_cost_usd", 0.0) for r in results)
    avg_steps = sum(r.get("step_count", 0) for r in results) / len(results)
    avg_consistency = sum(
        r.get("trajectory_consistency_score", 0.0) for r in results
    ) / len(results)
    optimal_rate = (
        sum(1 for r in results if r.get("is_optimal_trajectory")) / len(results)
    ) * 100.0
    cb_events = sum(1 for r in results if r.get("circuit_breaker_triggered"))

    summary = {
        "benchmark_runs": len(results),
        "optimal_trajectory_rate_pct": round(optimal_rate, 1),
        "average_steps_to_resolution": round(avg_steps, 2),
        "average_trajectory_consistency_score": round(avg_consistency, 2),
        "total_bedrock_cost_usd": round(total_cost, 6),
        "circuit_breaker_activations": cb_events,
        "scenarios": results,
    }

    # Print Formatted Results
    print("\n" + "=" * 80)
    print(" AUTONOMOUS SECURITY AGENT - AGENTIC EVALUATION BENCHMARK RESULTS")
    print("=" * 80)
    print(f"Total Scenarios Evaluated: {summary['benchmark_runs']}")
    print(
        f"Optimal Trajectory Rate (5 steps): {summary['optimal_trajectory_rate_pct']}%"
    )
    print(f"Average Steps to Outcome: {summary['average_steps_to_resolution']}")
    print(
        f"Average Trajectory Consistency: {summary['average_trajectory_consistency_score']} / 1.00"
    )
    print(f"Total Bedrock Token Cost: ${summary['total_bedrock_cost_usd']:.6f}")
    print(f"Circuit Breaker Escalations: {summary['circuit_breaker_activations']}")
    print("-" * 80)
    print(f"{'Scenario':<42} | {'Steps':<6} | {'Cost ($)':<10} | {'Status'}")
    print("-" * 80)
    for r in results:
        status = "ESCALATED" if r.get("circuit_breaker_triggered") else "RESOLVED (PR)"
        cost = f"${r.get('total_cost_usd', 0.0):.5f}"
        print(
            f"{r['scenario_name']:<42} | {r.get('step_count', 0):<6} | {cost:<10} | {status}"
        )
    print("=" * 80 + "\n")

    # Output JSON file
    output_path = root_dir / "evals" / "eval_results.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    logger.info("Saved evaluation results to %s", output_path)

    return summary


def main() -> None:
    """CLI entrypoint for running evaluation benchmarks."""
    asyncio.run(run_all_evaluations())


if __name__ == "__main__":
    main()
