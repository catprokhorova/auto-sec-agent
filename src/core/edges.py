"""Conditional routers and anti-loop circuit breaker logic for LangGraph."""

import logging
from typing import Literal

from src.core.config import get_settings
from src.core.state import AgentState

logger = logging.getLogger(__name__)

ValidationRoute = Literal["create_pr", "generate_fix", "escalate_to_human"]


def route_after_validation(state: AgentState) -> ValidationRoute:
    """Evaluate test validation result and enforce anti-loop circuit breaker.

    Routing rules:
    1. If sandbox tests passed -> route to 'create_pr' node.
    2. If tests failed:
       a. If loop_counter >= max_loop_count (default: 3) -> trip circuit breaker to 'escalate_to_human'.
       b. If duplicate patch detected in patch_history -> trip circuit breaker to 'escalate_to_human'.
       c. Otherwise -> loop back to 'generate_fix' node with error feedback.
    """
    settings = get_settings()
    max_loops = settings.max_loop_count

    # 1. Inspect test execution status
    test_res = state.test_reproduction_result or {}
    status = test_res.get("status", "FAILED")
    exit_code = test_res.get("exit_code", 1)

    if status == "PASSED" and exit_code == 0:
        logger.info(
            "Validation successful on attempt %d. Routing to 'create_pr'.",
            state.loop_counter,
        )
        return "create_pr"

    # 2. Check for duplicate patch oscillation in patch history
    history = state.patch_history
    if len(history) > 1 and history.count(history[-1]) > 1:
        logger.warning(
            "Circuit Breaker: Repetitive patch detected in attempt %d (hash: %s). Routing to 'escalate_to_human'.",
            state.loop_counter,
            history[-1][:8],
        )
        return "escalate_to_human"

    # 3. Check loop counter against hard circuit breaker threshold
    if state.loop_counter >= max_loops:
        logger.warning(
            "Circuit Breaker: loop_counter (%d) reached threshold (%d). Routing to 'escalate_to_human'.",
            state.loop_counter,
            max_loops,
        )
        return "escalate_to_human"

    # 4. Under limit and non-duplicate: loop back for self-correction
    logger.info(
        "Validation failed on attempt %d (exit code: %s). Looping back to 'generate_fix'.",
        state.loop_counter,
        exit_code,
    )
    return "generate_fix"
