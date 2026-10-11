"""FastAPI application for CI/CD webhook ingestion and agent triggering."""

import logging
import uuid
from typing import Any

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

from src.clients.langfuse_tracer import LangfuseTracer
from src.core.config import Settings, get_settings
from src.core.orchestrator import SecurityAgentOrchestrator

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Autonomous CI/CD Security Agent API",
    description="Webhook ingestion and automated remediation trigger for GitLab CI & GitHub Actions",
    version="1.0.0",
)


class CIWebhookPayload(BaseModel):
    """Payload model for CI pipeline webhook triggers."""

    provider: str = Field(
        default="generic",
        description="CI/CD provider (gitlab, github, generic)",
    )
    repo: str = Field(
        default="project/repository",
        description="Repository path or name",
    )
    branch: str = Field(
        default="main",
        description="Branch where pipeline failure or alert occurred",
    )
    error_log: str = Field(
        description="Raw test failure traceback, build log, or SAST alert",
    )
    target_file_path: str | None = Field(
        default=None,
        description="Optional target file hint if already identified by SAST scanner",
    )
    vulnerability_type: str | None = Field(
        default=None,
        description="Optional vulnerability classification or CWE/CVE ID",
    )
    async_execution: bool = Field(
        default=False,
        description="If True, dispatches remediation in background and returns accepted status",
    )


class WebhookResponse(BaseModel):
    """API response model for webhook trigger."""

    status: str
    run_id: str
    trace_id: str | None = None
    loop_counter: int = 0
    circuit_breaker_triggered: bool = False
    escalation_reason: str | None = None
    pr_info: dict[str, Any] | None = None
    metrics: dict[str, Any] | None = None


# Global dependencies
settings: Settings = get_settings()
tracer = LangfuseTracer(settings=settings)
orchestrator = SecurityAgentOrchestrator(tracer=tracer)


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "auto-sec-agent", "version": "1.0.0"}


@app.post(
    "/webhook/ci",
    response_model=WebhookResponse,
    status_code=status.HTTP_200_OK,
)
async def handle_ci_webhook(
    payload: CIWebhookPayload,
    background_tasks: BackgroundTasks,
    x_webhook_secret: str | None = Header(default=None, alias="X-Webhook-Secret"),
    x_gitlab_token: str | None = Header(default=None, alias="X-Gitlab-Token"),
) -> WebhookResponse:
    """Ingest CI/CD failure alerts and execute autonomous remediation."""
    # 1. Secret validation if configured
    configured_secret = settings.webhook_secret
    if configured_secret:
        received_token = x_webhook_secret or x_gitlab_token
        if received_token != configured_secret:
            logger.warning("Unauthorized webhook request rejected.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid webhook signature / token",
            )

    run_id = f"run_{uuid.uuid4().hex[:10]}"
    trace_id = f"trace_{uuid.uuid4().hex[:12]}"
    logger.info(
        "Received CI webhook from %s for repo '%s' (run_id: %s)",
        payload.provider,
        payload.repo,
        run_id,
    )

    # 2. Async Background Execution
    if payload.async_execution:
        background_tasks.add_task(
            orchestrator.run,
            error_log=payload.error_log,
            target_file_path=payload.target_file_path,
            vulnerability_type=payload.vulnerability_type,
            trace_id=trace_id,
        )
        return WebhookResponse(
            status="ACCEPTED",
            run_id=run_id,
            trace_id=trace_id,
            loop_counter=0,
            circuit_breaker_triggered=False,
        )

    # 3. Synchronous Execution
    final_state = await orchestrator.run(
        error_log=payload.error_log,
        target_file_path=payload.target_file_path,
        vulnerability_type=payload.vulnerability_type,
        trace_id=trace_id,
    )

    metrics = tracer.get_metrics(trace_id)

    outcome_status = (
        "ESCALATED" if final_state.circuit_breaker_triggered else "RESOLVED"
    )
    return WebhookResponse(
        status=outcome_status,
        run_id=run_id,
        trace_id=trace_id,
        loop_counter=final_state.loop_counter,
        circuit_breaker_triggered=final_state.circuit_breaker_triggered,
        escalation_reason=final_state.escalation_reason,
        pr_info=final_state.pr_info,
        metrics=metrics,
    )
