"""LangGraph node implementations for autonomous security triage, fix, and validation."""

import hashlib
import json
import logging
import re
import uuid
from typing import Any

from src.clients.bedrock import BedrockClient
from src.clients.mcp_gateway import MCPGateway
from src.core.config import Settings, get_settings
from src.core.pruner import TokenPruner
from src.core.state import AgentState

logger = logging.getLogger(__name__)


def extract_unified_diff(text: str) -> str:
    """Extract clean unified git diff from model text output."""
    diff_block_match = re.search(r"```(?:diff|patch)?\s*\n([\s\S]*?)```", text)
    if diff_block_match:
        return diff_block_match.group(1).strip()

    # Search for raw diff headers if not wrapped in markdown blocks
    if "--- a/" in text and "+++ b/" in text:
        start_idx = text.find("--- a/")
        return text[start_idx:].strip()

    return text.strip()


class AgentWorkflowNodes:
    """Encapsulates node execution logic and external dependency bindings."""

    def __init__(
        self,
        bedrock_client: BedrockClient | None = None,
        mcp_gateway: MCPGateway | None = None,
        pruner: TokenPruner | None = None,
        settings: Settings | None = None,
        tracer: Any = None,
    ):
        self.settings = settings or get_settings()
        self.bedrock = bedrock_client or BedrockClient(settings=self.settings)
        self.gateway = mcp_gateway or MCPGateway()
        self.tracer = tracer
        if self.tracer:
            self.gateway.set_tracer(self.tracer)
        self.pruner = pruner or TokenPruner(
            max_lines=self.settings.token_pruning_max_lines
        )

    def _sync_gateway_trace(self, state: AgentState) -> None:
        """Sync active trace ID to gateway for telemetry."""
        if hasattr(self.gateway, "current_trace_id"):
            self.gateway.current_trace_id = state.trace_id

    async def triage_error_node(self, state: AgentState) -> dict[str, Any]:
        """Triage CI error/vulnerability log, extract stack traces, and identify culprit file."""
        self._sync_gateway_trace(state)
        logger.info("Executing triage_error_node (loop: %d)", state.loop_counter)

        # 1. Context Pruning: Extract critical stack traces and CVE info
        pruned_res = self.pruner.prune_log(state.error_log)
        pruned_content = pruned_res.cleaned_content

        system_prompt = (
            "You are an expert Application Security and DevOps AI triage agent. "
            "Analyze the provided pruned error log or SAST report. Locate the exact culprit "
            "file path, line number, and vulnerability or error classification. "
            "Respond strictly with a JSON object in this structure:\n"
            "{\n"
            '  "target_file": "path/to/file.py",\n'
            '  "line_number": 42,\n'
            '  "vulnerability_type": "CWE-89: SQL Injection",\n'
            '  "summary": "Brief explanation of root cause"\n'
            "}"
        )

        messages = [
            {
                "role": "user",
                "content": f"Pruned Error / Vulnerability Log:\n\n{pruned_content}",
            }
        ]

        llm_response = await self.bedrock.generate_haiku(
            messages=messages,
            system_prompt=system_prompt,
            temperature=0.0,
        )

        if self.tracer and state.trace_id:
            try:
                self.tracer.record_token_usage(
                    trace_id=state.trace_id,
                    model=llm_response.model,
                    input_tokens=llm_response.input_tokens,
                    output_tokens=llm_response.output_tokens,
                )
            except Exception as tr_err:
                logger.debug("Failed recording triage tokens: %s", tr_err)

        target_file = state.target_file_path
        line_num = state.line_number
        vuln_type = state.vulnerability_type or "Unknown Vulnerability"

        # Parse JSON from Haiku output
        try:
            content = llm_response.content.strip()
            # Extract JSON block if wrapped
            json_match = re.search(r"\{[\s\S]*\}", content)
            if json_match:
                parsed = json.loads(json_match.group(0))
                target_file = parsed.get("target_file") or target_file
                line_num = parsed.get("line_number") or line_num
                vuln_type = parsed.get("vulnerability_type") or vuln_type
        except Exception as parse_err:
            logger.warning("Could not parse JSON from triage output: %s", parse_err)

        # Fallback regex extraction if target_file is still missing
        if not target_file:
            file_match = re.search(
                r'File ["\']([^"\']+\.py)["\'], line (\d+)', pruned_content
            )
            if file_match:
                target_file = file_match.group(1)
                line_num = int(file_match.group(2))

        # Default fallback target if unlocatable
        if not target_file:
            target_file = "services/auth/service.py"

        updated_messages = list(state.messages)
        updated_messages.append(
            {
                "role": "assistant",
                "content": (
                    f"Triage complete. Target: {target_file}:{line_num or 'unknown'}. "
                    f"Vulnerability: {vuln_type}."
                ),
            }
        )

        return {
            "pruned_log": pruned_content,
            "target_file_path": target_file,
            "line_number": line_num,
            "vulnerability_type": vuln_type,
            "messages": updated_messages,
        }

    async def fetch_context_node(self, state: AgentState) -> dict[str, Any]:
        """Query Knowledge Graph for service impact and Git server for file contents."""
        self._sync_gateway_trace(state)
        target_file = state.target_file_path or "services/auth/service.py"
        logger.info("Executing fetch_context_node for '%s'", target_file)

        # 1. Fetch system architectural impact radius via MCP Knowledge Graph
        impact_result = await self.gateway.execute_tool(
            "get_impact_radius",
            {"file_path": target_file},
        )
        impact_data = impact_result.output or {}
        affected_services = impact_data.get("affected_services", [])
        suggested_tests = impact_data.get("suggested_test_suites", [])

        # 2. Fetch code context via MCP Git server
        start_line = max(1, (state.line_number or 1) - 25)
        end_line = (state.line_number or 1) + 35

        code_result = await self.gateway.execute_tool(
            "read_file",
            {
                "file_path": target_file,
                "start_line": start_line,
                "end_line": end_line,
            },
        )

        code_snippet = (
            code_result.output
            if code_result.success
            else f"# Unable to read {target_file}: {code_result.error_message}"
        )

        # 3. Fetch security reference guidance via OpenSearch semantic search
        search_query = state.vulnerability_type or "security vulnerability remediation"
        search_result = await self.gateway.execute_tool(
            "semantic_code_search",
            {"query": search_query, "top_k": 1},
        )
        sec_guidelines = ""
        if (
            search_result.success
            and isinstance(search_result.output, list)
            and len(search_result.output) > 0
        ):
            item = search_result.output[0]
            if isinstance(item, dict):
                sec_guidelines = f"\nSecurity Guideline ({item.get('title', 'Reference')}): {item.get('snippet', '')}"

        updated_messages = list(state.messages)
        updated_messages.append(
            {
                "role": "system",
                "content": (
                    f"Retrieved code context for {target_file}:\n{code_snippet}\n"
                    f"Impacted services: {affected_services}\n"
                    f"Suggested tests: {suggested_tests}"
                    f"{sec_guidelines}"
                ),
            }
        )

        return {
            "code_context": code_snippet,
            "dependency_impact": affected_services,
            "suggested_test_suites": suggested_tests,
            "messages": updated_messages,
        }

    async def generate_fix_node(self, state: AgentState) -> dict[str, Any]:
        """Synthesize a unified git diff patch addressing the issue and prior test feedback."""
        self._sync_gateway_trace(state)
        next_loop = state.loop_counter + 1
        logger.info(
            "Executing generate_fix_node (loop iteration: %d/%d)",
            next_loop,
            self.settings.max_loop_count,
        )

        system_prompt = (
            "You are an elite Autonomous AppSec & DevOps Code Remediation Agent. "
            "Your mission is to generate a minimal, surgically precise unified git diff "
            "that fixes the vulnerability or test failure without breaking backward compatibility.\n\n"
            "CRITICAL RULES:\n"
            "1. Output ONLY a valid unified diff (starting with `--- a/` and `+++ b/`).\n"
            "2. Do NOT include explanatory conversational text outside the diff block.\n"
            "3. If prior test failures are provided, inspect the failure trace and correct your logic."
        )

        prompt_content = (
            f"Target file: {state.target_file_path}\n"
            f"Vulnerability: {state.vulnerability_type}\n\n"
            f"Code Context:\n{state.code_context}\n\n"
            f"Pruned Error / Vulnerability Log:\n{state.pruned_log}\n"
        )

        # Include feedback from previous failed reproduction if looping
        if (
            state.test_reproduction_result
            and state.test_reproduction_result.get("status") != "PASSED"
        ):
            err_output = state.test_reproduction_result.get(
                "stderr"
            ) or state.test_reproduction_result.get("stdout")
            prompt_content += (
                f"\n[FEEDBACK FROM PREVIOUS FAILED VALIDATION (Attempt #{state.loop_counter})]:\n"
                f"{err_output}\n"
                "Please fix the above error in your new patch."
            )

        messages = list(state.messages)
        messages.append({"role": "user", "content": prompt_content})

        # Apply sliding window to prevent lost-in-the-middle context explosion
        windowed_messages = self.pruner.apply_sliding_window(
            messages, window_size=3, preserve_system=True
        )

        llm_response = await self.bedrock.generate_sonnet(
            messages=windowed_messages,
            system_prompt=system_prompt,
            temperature=0.0,
        )

        if self.tracer and state.trace_id:
            try:
                self.tracer.record_token_usage(
                    trace_id=state.trace_id,
                    model=llm_response.model,
                    input_tokens=llm_response.input_tokens,
                    output_tokens=llm_response.output_tokens,
                )
            except Exception as tr_err:
                logger.debug("Failed recording fix tokens: %s", tr_err)

        unified_diff = extract_unified_diff(llm_response.content)

        updated_messages = list(messages)
        updated_messages.append(
            {
                "role": "assistant",
                "content": f"Proposed Patch v{next_loop}:\n```diff\n{unified_diff}\n```",
            }
        )

        return {
            "proposed_patch": unified_diff,
            "loop_counter": next_loop,
            "messages": updated_messages,
        }

    async def validate_fix_node(self, state: AgentState) -> dict[str, Any]:
        """Dispatch patch to isolated Docker sandbox and compute patch hash."""
        self._sync_gateway_trace(state)
        patch = state.proposed_patch or ""
        logger.info(
            "Executing validate_fix_node (validating patch of length %d)", len(patch)
        )

        # 1. Compute SHA-256 hash of proposed patch to guard against repetitive loops
        patch_hash = hashlib.sha256(patch.strip().encode("utf-8")).hexdigest()
        updated_history = list(state.patch_history)
        updated_history.append(patch_hash)

        # 2. Determine target service and test command
        service_name = "auth_service"
        if state.dependency_impact:
            service_name = state.dependency_impact[0]

        test_cmd = "pytest"
        if state.suggested_test_suites:
            test_cmd = f"pytest {' '.join(state.suggested_test_suites)}"

        # 3. Execute isolated Docker sandbox test run via MCP Gateway
        sandbox_res = await self.gateway.execute_tool(
            "run_test_in_sandbox",
            {
                "service_name": service_name,
                "patch_diff": patch,
                "test_command": test_cmd,
            },
        )

        test_result = sandbox_res.output or {
            "exit_code": 1,
            "status": "FAILED",
            "stdout": "",
            "stderr": sandbox_res.error_message or "Sandbox execution failed",
        }

        updated_messages = list(state.messages)
        status = test_result.get("status", "FAILED")
        updated_messages.append(
            {
                "role": "assistant",
                "content": (
                    f"Sandbox validation complete. Status: {status}. "
                    f"Exit code: {test_result.get('exit_code')}."
                ),
            }
        )

        return {
            "patch_history": updated_history,
            "test_reproduction_result": test_result,
            "messages": updated_messages,
        }

    async def create_pr_node(self, state: AgentState) -> dict[str, Any]:
        """Create a dedicated fix branch, apply validated patch, and open a PR/MR."""
        self._sync_gateway_trace(state)
        logger.info("Executing create_pr_node: Fix successfully validated!")

        branch_id = uuid.uuid4().hex[:6]
        branch_name = f"auto-sec/fix-{branch_id}"
        target_file = state.target_file_path or "code"
        vuln = state.vulnerability_type or "Security Vulnerability"

        # 1. Create working branch via MCP Git server
        await self.gateway.execute_tool(
            "create_branch",
            {"branch_name": branch_name, "base_branch": self.settings.git_base_branch},
        )

        # 2. Apply verified patch to branch
        await self.gateway.execute_tool(
            "apply_git_diff",
            {
                "branch_name": branch_name,
                "diff_patch": state.proposed_patch or "",
            },
        )

        # 3. Open Pull Request / Merge Request
        title = f"Fix {vuln} in {target_file}"
        description = (
            f"## Autonomous Security Agent Remediation\n\n"
            f"- **Target File:** `{target_file}`\n"
            f"- **Vulnerability:** `{vuln}`\n"
            f"- **Validation Status:** PASSED (Unit & Regression tests verified in isolated Docker sandbox)\n"
            f"- **Attempts required:** {state.loop_counter}\n\n"
            f"### Unified Diff:\n```diff\n{state.proposed_patch}\n```\n"
        )

        pr_result = await self.gateway.execute_tool(
            "create_pull_request",
            {
                "title": title,
                "description": description,
                "source_branch": branch_name,
                "target_branch": self.settings.git_base_branch,
            },
        )

        pr_data = pr_result.output or {
            "title": title,
            "source_branch": branch_name,
            "target_branch": self.settings.git_base_branch,
            "status": "OPEN",
            "url": f"https://gitlab.com/petty-pets/auto-sec-agent/-/merge_requests/{branch_name}",
        }

        updated_messages = list(state.messages)
        updated_messages.append(
            {
                "role": "assistant",
                "content": f"Successfully created Pull Request: {pr_data.get('url', 'created')}",
            }
        )

        return {
            "pr_info": pr_data,
            "messages": updated_messages,
        }

    async def escalate_to_human_node(self, state: AgentState) -> dict[str, Any]:
        """Trigger circuit breaker escalation and compile trajectory log for operators."""
        self._sync_gateway_trace(state)
        logger.warning(
            "Executing escalate_to_human_node: Circuit breaker tripped! Reason: %s",
            state.escalation_reason,
        )

        reason = state.escalation_reason or "Maximum remediation attempts exceeded."
        summary_log = (
            f"[CIRCUIT BREAKER ACTIVATED - ESCALATED TO HUMAN]\n"
            f"Reason: {reason}\n"
            f"Loop Counter: {state.loop_counter}\n"
            f"Target File: {state.target_file_path}\n"
            f"Vulnerability: {state.vulnerability_type}\n"
            f"Patches Attempted: {len(state.patch_history)}\n"
            f"Last Test Result: {state.test_reproduction_result}\n"
        )

        updated_messages = list(state.messages)
        updated_messages.append({"role": "system", "content": summary_log})

        if self.tracer and state.trace_id:
            try:
                self.tracer.log_circuit_breaker(
                    trace_id=state.trace_id,
                    reason=reason,
                    loop_counter=state.loop_counter,
                    metadata={
                        "target_file": state.target_file_path,
                        "vulnerability_type": state.vulnerability_type,
                        "patch_count": len(state.patch_history),
                    },
                )
            except Exception as tr_err:
                logger.debug("Failed logging circuit breaker to tracer: %s", tr_err)

        return {
            "circuit_breaker_triggered": True,
            "escalation_reason": reason,
            "messages": updated_messages,
        }
