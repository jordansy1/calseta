"""Orchestrator — ties MCP data access, prompt building, LLM analysis, and finding submission together."""

from __future__ import annotations

import asyncio
import logging

from agents.security_analyst.analyst import analyze as analyze_llm
from agents.security_analyst.config import Config
from agents.security_analyst.mcp_client import MCPClient
from agents.security_analyst.models import AnalysisResult
from agents.security_analyst.prompt import build_analysis_prompt

logger = logging.getLogger(__name__)

try:
    from langsmith import traceable
except ImportError:
    def traceable(**kwargs):  # type: ignore[misc]
        def decorator(fn):  # type: ignore[no-untyped-def]
            return fn
        return decorator


@traceable(name="analyze_alert", run_type="chain")
async def analyze_alert(
    alert_uuid: str,
    config: Config,
    mcp: MCPClient,
    *,
    dry_run: bool = False,
) -> AnalysisResult | None:
    """Run the full analysis pipeline for a single alert.

    Steps:
    1. Fetch enriched alert data via MCP
    2. Build analysis prompt
    3. Call Claude Code (unless dry_run)
    4. Post finding back to Calseta (unless dry_run)
    """
    # Step 1: Fetch alert data
    logger.info("Fetching alert data", extra={"alert_uuid": alert_uuid})
    data = await mcp.fetch_alert_data(alert_uuid)

    # Step 2: Build prompt
    system_prompt, user_prompt = build_analysis_prompt(data)

    if dry_run:
        print(f"\n{'='*60}")
        print("DRY RUN — Prompt that would be sent to Claude Code:")
        print(f"{'='*60}")
        print(f"\n--- SYSTEM PROMPT ---\n{system_prompt[:500]}...")
        print(f"\n--- USER PROMPT ---\n{user_prompt}")
        print(f"\n{'='*60}")
        return None

    # Step 3: Call Claude Code (blocking — offloaded to thread pool)
    logger.info("Calling Claude Code", extra={"model": config.model})
    result = await asyncio.to_thread(analyze_llm, system_prompt, user_prompt, config)

    # Step 4: Post finding back to Calseta
    try:
        finding_id = await mcp.post_finding(
            alert_uuid=alert_uuid,
            summary=result.summary,
            confidence=result.confidence,
            recommended_action=result.recommended_action,
            evidence=result.evidence,
        )
        logger.info("Finding posted", extra={"finding_id": finding_id, "alert_uuid": alert_uuid})
    except Exception:
        logger.exception("Failed to post finding — analysis still available in stdout")

    return result


async def run_single(alert_uuid: str, config: Config, *, dry_run: bool = False) -> None:
    """Analyze a single alert."""
    async with MCPClient(config) as mcp:
        result = await analyze_alert(alert_uuid, config, mcp, dry_run=dry_run)
        if result:
            _print_result(alert_uuid, result)


async def run_batch(config: Config, *, max_alerts: int = 10) -> None:
    """Analyze all open, enriched alerts up to max_alerts."""
    async with MCPClient(config) as mcp:
        processed = 0
        posted = 0
        skipped = 0
        page = 1

        while processed < max_alerts:
            search_result = await mcp.search_open_alerts(page=page, page_size=50)
            alerts = search_result.get("alerts", [])
            if not alerts:
                break

            for alert_info in alerts:
                if processed >= max_alerts:
                    break

                alert_uuid = alert_info["uuid"]
                processed += 1

                try:
                    result = await analyze_alert(alert_uuid, config, mcp)
                    if result:
                        _print_result(alert_uuid, result)
                        posted += 1
                except Exception:
                    logger.exception("Error analyzing alert", extra={"alert_uuid": alert_uuid})
                    skipped += 1

            page += 1

        print(f"\nProcessed {processed} alerts: {posted} findings posted, {skipped} skipped (errors)")


def _print_result(alert_uuid: str, result: AnalysisResult) -> None:
    """Print analysis result summary to stdout."""
    print(f"\n--- Alert: {alert_uuid} ---")
    print(f"Assessment: {result.assessment}")
    print(f"Confidence: {result.confidence}")
    if result.recommended_action:
        print(f"Recommended: {result.recommended_action}")
    if result.cost_usd is not None:
        print(f"Cost: ${result.cost_usd:.4f}")
    print(f"\n{result.summary[:500]}")
    if len(result.summary) > 500:
        print("... (truncated)")
