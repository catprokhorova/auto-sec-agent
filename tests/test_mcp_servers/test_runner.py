"""Unit tests for standalone MCP server runner CLI."""

import pytest

from src.mcp_servers.runner import parse_args, SERVER_FACTORIES


def test_parse_args_git():
    """Verify git server arguments are parsed."""
    args = parse_args(["--server", "git", "--transport", "stdio"])
    assert args.server == "git"
    assert args.transport == "stdio"


def test_parse_args_sandbox_sse():
    """Verify sandbox server and SSE options are parsed."""
    args = parse_args(["--server", "sandbox", "--transport", "sse", "--port", "9000"])
    assert args.server == "sandbox"
    assert args.transport == "sse"
    assert args.port == 9000


def test_parse_args_knowledge():
    """Verify knowledge server arguments are parsed."""
    args = parse_args(["--server", "knowledge"])
    assert args.server == "knowledge"
    assert args.transport == "stdio"


def test_server_factories_registered():
    """Verify all 3 servers are present in SERVER_FACTORIES."""
    assert "git" in SERVER_FACTORIES
    assert "sandbox" in SERVER_FACTORIES
    assert "knowledge" in SERVER_FACTORIES
