"""State models for LangGraph autonomous security agent workflow."""

from typing import Any

from pydantic import BaseModel, Field


class AgentState(BaseModel):
    """Global state container for the Autonomous CI/CD Security Agent."""

    # 1. Inputs & Sanitization
    error_log: str = Field(
        default="",
        description="Raw error log, test failure output, or SAST alert from CI/CD pipeline",
    )
    pruned_log: str = Field(
        default="",
        description="Token-pruned critical stack trace, failure summary, and CVE identifiers",
    )

    # 2. Context & Root Cause Analysis
    target_file_path: str | None = Field(
        default=None,
        description="Relative repository path of the culprit file identified for fix",
    )
    line_number: int | None = Field(
        default=None,
        description="Line number where the error or vulnerability was detected",
    )
    vulnerability_type: str | None = Field(
        default=None,
        description="Identified vulnerability classification (e.g. CWE-89 SQLi) or error type",
    )
    code_context: str | None = Field(
        default=None,
        description="Extracted source code snippet around the culprit lines",
    )
    dependency_impact: list[str] = Field(
        default_factory=list,
        description="List of upstream/downstream microservices and modules affected",
    )
    suggested_test_suites: list[str] = Field(
        default_factory=list,
        description="Test files recommended to validate the remediation",
    )

    # 3. Patch Generation & History
    proposed_patch: str | None = Field(
        default=None,
        description="Unified git diff patch proposed by the cognitive engine",
    )
    patch_history: list[str] = Field(
        default_factory=list,
        description="SHA-256 hashes of previously attempted patches to detect loop repetition",
    )

    # 4. Sandbox Validation & Resilience Guard
    test_reproduction_result: dict[str, Any] | None = Field(
        default=None,
        description="Execution results from isolated Docker sandbox runner",
    )
    loop_counter: int = Field(
        default=0,
        description="Number of patch generation and test validation cycles executed",
    )
    circuit_breaker_triggered: bool = Field(
        default=False,
        description="True if the anti-loop circuit breaker was activated",
    )
    escalation_reason: str | None = Field(
        default=None,
        description="Explanatory reason when execution escalates to human operator",
    )

    # 5. Output Artifacts
    pr_info: dict[str, Any] | None = Field(
        default=None,
        description="Pull Request or Merge Request details upon successful patch",
    )
    messages: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Sliding window conversation trajectory and intermediate reasoning messages",
    )
