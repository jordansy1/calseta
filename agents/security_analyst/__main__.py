"""CLI entry point: python -m agents.security_analyst"""

from __future__ import annotations

import argparse
import asyncio
import logging
import shutil
import sys

from agents.security_analyst.agent import run_batch, run_single
from agents.security_analyst.config import Config


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calseta Security Analyst Agent — analyze enriched alerts with Claude Code"
    )
    parser.add_argument("--alert-uuid", help="UUID of a specific alert to analyze")
    parser.add_argument("--all-open", action="store_true", help="Analyze all open, enriched alerts")
    parser.add_argument("--max-alerts", type=int, default=10, help="Max alerts in batch mode (default: 10)")
    parser.add_argument("--dry-run", action="store_true", help="Fetch data and build prompt, but don't call LLM")
    parser.add_argument("--model", help="Override Claude Code model (sonnet, opus, haiku)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    # Validate arguments
    if not args.alert_uuid and not args.all_open:
        parser.error("Either --alert-uuid or --all-open is required")

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Check Claude Code is installed (fail fast)
    if not args.dry_run and shutil.which("claude") is None:
        print("ERROR: Claude Code CLI not found. Install: https://docs.anthropic.com/en/docs/claude-code", file=sys.stderr)
        sys.exit(1)

    # Load config
    try:
        config = Config()
    except (KeyError, ValueError) as exc:
        print(f"ERROR: Configuration error: {exc}", file=sys.stderr)
        print("See agents/security_analyst/.env.example for required variables.", file=sys.stderr)
        sys.exit(1)

    # Override model if specified — reconstruct to re-validate via __post_init__
    if args.model:
        config = Config(
            mcp_url=config.mcp_url,
            api_key=config.api_key,
            model=args.model,
            timeout=config.timeout,
        )

    # Run
    if args.alert_uuid:
        asyncio.run(run_single(args.alert_uuid, config, dry_run=args.dry_run))
    else:
        asyncio.run(run_batch(config, max_alerts=args.max_alerts))


if __name__ == "__main__":
    main()
