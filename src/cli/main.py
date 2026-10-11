"""CLI entrypoint for executing autonomous security remediations from the terminal or CI scripts."""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from src.clients.langfuse_tracer import LangfuseTracer
from src.core.config import get_settings
from src.core.nodes import AgentWorkflowNodes
from src.core.orchestrator import SecurityAgentOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("auto-sec-cli")


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Autonomous CI/CD Security Agent CLI - Triage, synthesize, and validate fixes."
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    run_parser = subparsers.add_parser(
        "run", help="Run remediation pipeline on an error log"
    )
    run_parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Path to file containing raw CI test traceback or SAST alert (reads from stdin if omitted or '-')",
    )
    run_parser.add_argument(
        "--repo",
        type=str,
        default="local/repository",
        help="Repository identifier or directory path",
    )
    run_parser.add_argument(
        "--target-file",
        type=str,
        default=None,
        help="Optional culprit file hint",
    )
    run_parser.add_argument(
        "--vulnerability-type",
        type=str,
        default=None,
        help="Optional vulnerability classification hint (e.g. CWE-89)",
    )
    run_parser.add_argument(
        "--max-loops",
        type=int,
        default=3,
        help="Anti-loop circuit breaker maximum attempt threshold (default: 3)",
    )
    run_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug-level logging",
    )

    return parser


async def execute_run(args: argparse.Namespace) -> int:
    """Execute remediation pipeline based on CLI arguments. Returns exit code."""
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # 1. Read input error log
    if args.log_file and args.log_file != "-":
        log_path = Path(args.log_file)
        if not log_path.exists():
            logger.error("Error log file not found: %s", args.log_file)
            return 1
        error_log = log_path.read_text(encoding="utf-8")
    else:
        # Read from stdin
        if sys.stdin.isatty():
            logger.error(
                "No log file provided and stdin is empty. Provide --log-file or pipe error log."
            )
            return 1
        error_log = sys.stdin.read()

    if not error_log.strip():
        logger.error("Input error log is empty.")
        return 1

    settings = get_settings()
    settings.max_loop_count = args.max_loops

    tracer = LangfuseTracer(settings=settings)
    nodes = AgentWorkflowNodes(settings=settings, tracer=tracer)
    orchestrator = SecurityAgentOrchestrator(nodes=nodes, tracer=tracer)

    logger.info("Triggering autonomous security remediation for %s...", args.repo)
    final_state = await orchestrator.run(
        error_log=error_log,
        target_file_path=args.target_file,
        vulnerability_type=args.vulnerability_type,
    )

    # Display results
    print("\n" + "=" * 65)
    print(" REMEDIATION SUMMARY")
    print("=" * 65)
    print(f"Target File Identified: {final_state.target_file_path}")
    print(f"Vulnerability Type:     {final_state.vulnerability_type}")
    print(f"Attempts Executed:      {final_state.loop_counter}")
    print(
        f"Circuit Breaker:        {'TRIPPED' if final_state.circuit_breaker_triggered else 'NORMAL'}"
    )

    if final_state.circuit_breaker_triggered:
        print(f"Escalation Reason:      {final_state.escalation_reason}")
        print("=" * 65 + "\n")
        logger.warning("Pipeline escalated to human operator.")
        return 1

    if final_state.pr_info:
        print(f"Pull Request Created:   {final_state.pr_info.get('url', 'Created')}")
        print(f"PR Status:              {final_state.pr_info.get('status', 'OPEN')}")
        print("=" * 65 + "\n")
        logger.info("Autonomous remediation succeeded.")
        return 0

    print("=" * 65 + "\n")
    return 0


def main() -> None:
    """CLI script entrypoint."""
    parser = build_parser()

    # If no arguments given or 'run' omitted, default to run with help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # If first arg is not a known subcommand and looks like a flag, insert 'run'
    if sys.argv[1] not in ["run", "-h", "--help"]:
        sys.argv.insert(1, "run")

    args = parser.parse_args()
    if args.command == "run":
        exit_code = asyncio.run(execute_run(args))
        sys.exit(exit_code)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
