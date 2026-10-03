"""Standalone CLI runner for executing MCP servers via stdio or SSE transport."""

import argparse
import sys
from typing import Callable, Dict

from src.mcp_servers.git_server import create_git_mcp_server
from src.mcp_servers.knowledge_server import create_knowledge_mcp_server
from src.mcp_servers.sandbox_server import create_sandbox_mcp_server

SERVER_FACTORIES: Dict[str, Callable[[], object]] = {
    "git": create_git_mcp_server,
    "sandbox": create_sandbox_mcp_server,
    "knowledge": create_knowledge_mcp_server,
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command line arguments for MCP runner."""
    parser = argparse.ArgumentParser(
        description="Run standalone MCP server for Autonomous Security Agent"
    )
    parser.add_argument(
        "--server",
        choices=["git", "sandbox", "knowledge"],
        required=True,
        help="Name of the MCP server to launch",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport protocol: 'stdio' (default) or 'sse'",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port number when using SSE transport (default: 8000)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Launch the chosen MCP server."""
    args = parse_args(argv)
    factory = SERVER_FACTORIES[args.server]
    server = factory()

    # If FastMCP is not available or server is returned as raw service
    if not hasattr(server, "run"):
        sys.stderr.write(
            f"Error: FastMCP runtime not detected for server '{args.server}'. "
            "Ensure the 'mcp' package is installed.\n"
        )
        sys.exit(1)

    sys.stderr.write(
        f"Starting MCP server '{args.server}' using transport '{args.transport}'...\n"
    )

    if args.transport == "stdio":
        server.run(transport="stdio")
    elif args.transport == "sse":
        # FastMCP run with sse
        server.run(transport="sse")


if __name__ == "__main__":
    main()
