"""Token-efficient log pruning and sliding window context management."""

import json
import re
from typing import Any

from pydantic import BaseModel, Field

from src.core.config import get_settings


class PrunedLogResult(BaseModel):
    """Structured result of log pruning and context extraction."""

    original_line_count: int = Field(description="Number of lines in the raw input log")
    pruned_line_count: int = Field(description="Number of lines in the pruned output")
    reduction_ratio: float = Field(
        description="Percentage of lines removed from original log (0.0 - 1.0)"
    )
    extracted_cves: list[str] = Field(
        default_factory=list, description="Extracted CVE/CWE identifiers"
    )
    stack_traces: list[str] = Field(
        default_factory=list, description="Extracted stack traces or failure blocks"
    )
    sast_findings: list[str] = Field(
        default_factory=list,
        description="Extracted SAST or security vulnerability findings",
    )
    cleaned_content: str = Field(
        description="Sanitized, token-efficient log text ready for LLM input"
    )


class TokenPruner:
    """Sanitizes raw build/test logs and manages LLM message windowing."""

    # Common stack trace and failure patterns
    PYTHON_TRACEBACK_PATTERN = re.compile(
        r"(Traceback \(most recent call last\):[\s\S]*?(?=\n(?:[A-Z][a-zA-Z0-9_]*Error|[A-Z][a-zA-Z0-9_]*Exception):[^\n]*\n|\Z)[^\n]*)",
        re.MULTILINE,
    )
    PYTEST_FAILURES_PATTERN = re.compile(
        r"(={3,}\s*FAILURES\s*={3,}[\s\S]*?(?=={3,}|\Z))",
        re.MULTILINE,
    )
    PYTEST_SUMMARY_PATTERN = re.compile(
        r"(={3,}\s*short test summary info\s*={3,}[\s\S]*?(?=={3,}|\Z))",
        re.MULTILINE,
    )
    CVE_CWE_PATTERN = re.compile(
        r"\b(?:CVE-\d{4}-\d{4,7}|CWE-\d{1,5})\b", re.IGNORECASE
    )
    SAST_SEVERITY_PATTERN = re.compile(
        r"^(?:.*(?:\[(?:CRITICAL|HIGH|MEDIUM|LOW|ERROR|WARNING)\]|Severity:\s*(?:CRITICAL|HIGH|MEDIUM|LOW)).*)$",
        re.IGNORECASE | re.MULTILINE,
    )

    # Patterns indicating build noise to discard
    NOISE_PATTERNS = [
        re.compile(
            r"^\s*\[INFO\]\s+.*(?:download|downloading|fetched|extracting)",
            re.IGNORECASE,
        ),
        re.compile(
            r"^\s*Step \d+/\d+\s*:\s*(?:FROM|WORKDIR|COPY|ENV|LABEL|EXPOSE|USER)",
            re.IGNORECASE,
        ),
        re.compile(r"^\s*(?:Get|Hit|Ign):\d+\s+http", re.IGNORECASE),
        re.compile(r"^\s*Requirement already satisfied:", re.IGNORECASE),
        re.compile(r"^\s*Collecting\s+[\w\.-]+", re.IGNORECASE),
        re.compile(r"^\s*Downloading\s+[\w\.-]+", re.IGNORECASE),
        re.compile(r"^\s*Installing collected packages:", re.IGNORECASE),
    ]

    def __init__(self, max_lines: int | None = None):
        settings = get_settings()
        self.max_lines = max_lines or settings.token_pruning_max_lines

    def extract_cves(self, text: str) -> list[str]:
        """Extract unique CVE and CWE identifiers from text."""
        matches = self.CVE_CWE_PATTERN.findall(text)
        # Deduplicate preserving uppercase format
        return sorted({m.upper() for m in matches})

    def extract_stack_traces(self, raw_log: str) -> list[str]:
        """Extract Python and pytest failure blocks from raw log."""
        traces: list[str] = []

        for match in self.PYTHON_TRACEBACK_PATTERN.finditer(raw_log):
            trace = match.group(1).strip()
            if trace and trace not in traces:
                traces.append(trace)

        for match in self.PYTEST_FAILURES_PATTERN.finditer(raw_log):
            block = match.group(1).strip()
            if block and block not in traces:
                traces.append(block)

        for match in self.PYTEST_SUMMARY_PATTERN.finditer(raw_log):
            block = match.group(1).strip()
            if block and block not in traces:
                traces.append(block)

        return traces

    def extract_sast_findings(self, raw_log: str) -> list[str]:
        """Extract SAST vulnerability alert blocks or embedded JSON results."""
        findings: list[str] = []

        # 1. Check for embedded JSON payload (e.g., Semgrep / GitLab SAST JSON)
        try:
            # Look for JSON arrays or objects in the log
            for line in raw_log.splitlines():
                stripped = line.strip()
                if (stripped.startswith("{") and stripped.endswith("}")) or (
                    stripped.startswith("[") and stripped.endswith("]")
                ):
                    try:
                        data = json.loads(stripped)
                        if isinstance(data, dict) and any(
                            k in data
                            for k in [
                                "results",
                                "vulnerabilities",
                                "findings",
                                "check_id",
                            ]
                        ):
                            findings.append(json.dumps(data, indent=2))
                    except Exception:
                        pass
        except Exception:
            pass

        # 2. Extract severity-tagged lines
        for match in self.SAST_SEVERITY_PATTERN.finditer(raw_log):
            line = match.group(0).strip()
            if line and line not in findings:
                findings.append(line)

        return findings

    def _is_noise_line(self, line: str) -> bool:
        """Check if a line matches known noise patterns."""
        return any(pattern.search(line) is not None for pattern in self.NOISE_PATTERNS)

    def prune_log(self, raw_log: str, max_lines: int | None = None) -> PrunedLogResult:
        """Prune verbose CI build/test log to only critical stack traces and alerts."""
        limit = max_lines or self.max_lines
        lines = raw_log.splitlines()
        original_count = len(lines)

        extracted_cves = self.extract_cves(raw_log)
        stack_traces = self.extract_stack_traces(raw_log)
        sast_findings = self.extract_sast_findings(raw_log)

        # Assemble extracted critical blocks
        critical_sections: list[str] = []

        if extracted_cves:
            critical_sections.append(
                "[IDENTIFIED VULNERABILITIES]\n"
                + "\n".join(f"- {cve}" for cve in extracted_cves)
            )

        if sast_findings:
            critical_sections.append(
                "[SAST FINDINGS & ALERTS]\n" + "\n".join(sast_findings[:15])
            )

        if stack_traces:
            critical_sections.append(
                "[CRITICAL STACK TRACES & TEST FAILURES]\n"
                + "\n\n---\n\n".join(stack_traces[:10])
            )

        if critical_sections:
            assembled = "\n\n".join(critical_sections)
            pruned_lines = assembled.splitlines()
            if len(pruned_lines) > limit:
                # Keep head and tail of critical sections
                head_count = int(limit * 0.7)
                tail_count = limit - head_count - 1
                pruned_lines = (
                    pruned_lines[:head_count]
                    + [
                        f"... [Truncated {len(pruned_lines) - limit} lines of details] ..."
                    ]
                    + pruned_lines[-tail_count:]
                )
                assembled = "\n".join(pruned_lines)
        else:
            # Fallback heuristic: remove noisy dependency installation lines and retain error context
            filtered: list[str] = []
            for line in lines:
                if not self._is_noise_line(line):
                    filtered.append(line)

            if len(filtered) > limit:
                # Retain lines containing failure or error keywords
                priority_lines: list[str] = []
                for idx, line in enumerate(filtered):
                    lowered = line.lower()
                    if any(
                        kw in lowered
                        for kw in ["error", "fail", "fatal", "exception", "cve", "vuln"]
                    ):
                        start_idx = max(0, idx - 2)
                        end_idx = min(len(filtered), idx + 3)
                        for ctx_idx in range(start_idx, end_idx):
                            priority_lines.append(filtered[ctx_idx])

                if priority_lines:
                    # Deduplicate preserving order
                    seen = set()
                    deduped = [
                        x for x in priority_lines if not (x in seen or seen.add(x))
                    ]
                    filtered = deduped[:limit]
                else:
                    filtered = filtered[-limit:]

            assembled = "\n".join(filtered)
            pruned_lines = assembled.splitlines()

        pruned_count = len(pruned_lines)
        reduction = (
            round(1.0 - (pruned_count / original_count), 4)
            if original_count > 0
            else 0.0
        )

        return PrunedLogResult(
            original_line_count=original_count,
            pruned_line_count=pruned_count,
            reduction_ratio=max(0.0, reduction),
            extracted_cves=extracted_cves,
            stack_traces=stack_traces,
            sast_findings=sast_findings,
            cleaned_content=assembled,
        )

    def apply_sliding_window(
        self,
        messages: list[dict[str, Any]],
        window_size: int = 3,
        preserve_system: bool = True,
    ) -> list[dict[str, Any]]:
        """Manage context window by preserving system prompt and recent iterations.

        Keeps system instructions and the last `window_size` steps, summarizing
        intermediate exchanges into a concise historical context node to prevent
        'Lost in the Middle' traps and token window explosion.
        """
        if not messages:
            return []

        system_messages: list[dict[str, Any]] = []
        dialogue_messages: list[dict[str, Any]] = []

        for msg in messages:
            if preserve_system and msg.get("role") == "system":
                system_messages.append(msg)
            else:
                dialogue_messages.append(msg)

        if len(dialogue_messages) <= window_size:
            return system_messages + dialogue_messages

        # Older messages beyond the sliding window
        older_messages = dialogue_messages[:-window_size]
        recent_messages = dialogue_messages[-window_size:]

        # Create compact summary of older iterations
        summary_entries: list[str] = []
        for idx, msg in enumerate(older_messages, start=1):
            role = msg.get("role", "unknown")
            content = str(msg.get("content", ""))
            # Truncate content to 120 chars for the summary bullet
            snippet = content.replace("\n", " ").strip()
            if len(snippet) > 120:
                snippet = f"{snippet[:117]}..."
            summary_entries.append(f"Step {idx} ({role}): {snippet}")

        condensed_summary = {
            "role": "system",
            "content": (
                "[Historical Iterations Summary - Context Pruned]\n"
                + "\n".join(summary_entries)
            ),
        }

        return system_messages + [condensed_summary] + recent_messages
