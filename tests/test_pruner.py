"""Unit tests for TokenPruner, stack trace extraction, and sliding window context management."""

import pytest

from src.core.pruner import TokenPruner


@pytest.fixture
def pruner() -> TokenPruner:
    """Fixture providing a configured TokenPruner."""
    return TokenPruner(max_lines=200)


def test_extract_cves(pruner: TokenPruner):
    """Verify regex extraction and normalization of CVE and CWE IDs."""
    text = (
        "Detected vulnerability CVE-2023-38606 and CWE-89 in service.py. "
        "Also flagged cve-2021-44228 and cwe-79."
    )
    cves = pruner.extract_cves(text)
    assert "CVE-2023-38606" in cves
    assert "CVE-2021-44228" in cves
    assert "CWE-89" in cves
    assert "CWE-79" in cves


def test_extract_stack_traces(pruner: TokenPruner, sample_python_traceback: str):
    """Verify extraction of Python traceback and pytest failures."""
    traces = pruner.extract_stack_traces(sample_python_traceback)
    assert len(traces) >= 1
    assert any("sqlite3.OperationalError" in t for t in traces)


def test_extract_sast_findings(pruner: TokenPruner):
    """Verify extraction of SAST alerts and JSON findings."""
    log_with_sast = """
[INFO] Scanning repository...
[HIGH] services/auth/service.py:18 - Hardcoded secret detected
[CRITICAL] SQL Injection vulnerability in execute_query()
{"results": [{"check_id": "python.sqli", "path": "services/auth/service.py", "severity": "ERROR"}]}
[INFO] Scan finished with 2 issues.
"""
    findings = pruner.extract_sast_findings(log_with_sast)
    assert any("Hardcoded secret" in f for f in findings)
    assert any("SQL Injection" in f for f in findings)
    assert any("python.sqli" in f for f in findings)


def test_prune_10000_line_noisy_log(pruner: TokenPruner, sample_python_traceback: str):
    """Verify reduction of a 10,000+ line noisy CI build log down to critical failure blocks."""
    # Build 10,000 lines of container build/pip noise
    noise_lines = [
        f"[INFO] Step {i}/10000: Downloading package dependency-cache-{i}.whl"
        for i in range(10000)
    ]
    # Embed critical failure in the middle
    huge_log = (
        "\n".join(noise_lines[:5000])
        + "\n"
        + sample_python_traceback
        + "\n"
        + "\n".join(noise_lines[5000:])
    )

    result = pruner.prune_log(huge_log, max_lines=200)

    # Validate extreme token reduction
    assert result.original_line_count > 10000
    assert result.pruned_line_count <= 200
    assert result.reduction_ratio > 0.95
    assert len(result.stack_traces) > 0
    assert "OperationalError" in result.cleaned_content
    assert "[CRITICAL STACK TRACES & TEST FAILURES]" in result.cleaned_content


def test_sliding_window_context_management(pruner: TokenPruner):
    """Verify sliding window retains system instructions and last N messages while summarizing earlier steps."""
    messages = [
        {"role": "system", "content": "You are an autonomous CI/CD security agent."},
        {"role": "user", "content": "Initial CI error: Test failed in auth service."},
        {"role": "assistant", "content": "I will inspect services/auth/service.py."},
        {
            "role": "user",
            "content": "Here is the code context: def authenticate(): ...",
        },
        {
            "role": "assistant",
            "content": "I propose patch v1 with parameterized query.",
        },
        {"role": "user", "content": "Test failed with SyntaxError on line 18."},
        {"role": "assistant", "content": "I am fixing the syntax error in patch v2."},
        {"role": "user", "content": "Tests now passed."},
    ]

    # Keep window_size = 3
    windowed = pruner.apply_sliding_window(
        messages, window_size=3, preserve_system=True
    )

    # First message should still be the original system prompt
    assert windowed[0]["role"] == "system"
    assert "autonomous CI/CD security agent" in windowed[0]["content"]

    # Second message should be condensed summary of older messages
    assert windowed[1]["role"] == "system"
    assert "[Historical Iterations Summary - Context Pruned]" in windowed[1]["content"]

    # Last 3 messages should be preserved verbatim
    assert len(windowed) == 1 + 1 + 3  # system + summary + 3 recent
    assert windowed[-1]["content"] == "Tests now passed."
    assert windowed[-2]["content"] == "I am fixing the syntax error in patch v2."
    assert windowed[-3]["content"] == "Test failed with SyntaxError on line 18."


def test_sliding_window_within_limit(pruner: TokenPruner):
    """Verify messages within window size are preserved untouched."""
    messages = [
        {"role": "system", "content": "System prompt"},
        {"role": "user", "content": "Msg 1"},
        {"role": "assistant", "content": "Msg 2"},
    ]
    windowed = pruner.apply_sliding_window(messages, window_size=3)
    assert windowed == messages
