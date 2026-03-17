"""MCP client — connects to Calseta's MCP server via SSE.

Provides async context manager for connection lifecycle and methods for
reading alert resources and calling tools.
"""

from __future__ import annotations

import json
import logging
from contextlib import AsyncExitStack
from types import TracebackType

from mcp import ClientSession
from mcp.client.sse import sse_client

from agents.security_analyst.config import Config

logger = logging.getLogger(__name__)

try:
    from langsmith import traceable
except ImportError:
    def traceable(**kwargs):  # type: ignore[misc]
        def decorator(fn):  # type: ignore[no-untyped-def]
            return fn
        return decorator


class MCPClient:
    """Async context manager wrapping an MCP SSE client session."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._session: ClientSession | None = None
        self._exit_stack: AsyncExitStack | None = None

    async def __aenter__(self) -> MCPClient:
        self._exit_stack = AsyncExitStack()
        await self._exit_stack.__aenter__()

        url = self._config.mcp_url
        headers = {"Authorization": f"Bearer {self._config.api_key}"}
        read_stream, write_stream = await self._exit_stack.enter_async_context(
            sse_client(url=url, headers=headers)
        )
        session = ClientSession(read_stream, write_stream)
        self._session = await self._exit_stack.enter_async_context(session)
        await self._session.initialize()
        logger.info("MCP connection established", extra={"url": url})
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._exit_stack:
            await self._exit_stack.__aexit__(exc_type, exc_val, exc_tb)
        logger.info("MCP connection closed")

    async def read_resource(self, uri: str) -> str:
        """Read an MCP resource by URI and return its text content."""
        assert self._session is not None, "MCPClient not connected"
        result = await self._session.read_resource(uri)
        # MCP SDK returns ReadResourceResult with .contents list
        for content_block in result.contents:
            if hasattr(content_block, "text") and content_block.text:
                return content_block.text
        return ""

    async def call_tool(self, name: str, arguments: dict) -> str:
        """Call an MCP tool and return its text result.

        Only the first content block is returned. If the response contains
        multiple blocks, a warning is logged — callers should be aware that
        additional data (e.g. error details) may be present.
        """
        assert self._session is not None, "MCPClient not connected"
        result = await self._session.call_tool(name, arguments)
        if result.content:
            if len(result.content) > 1:
                logger.warning(
                    "MCP tool returned %d content blocks, using first only",
                    len(result.content),
                    extra={"tool": name},
                )
            return result.content[0].text or ""
        return ""

    @traceable(name="fetch_alert_data", run_type="retriever")
    async def fetch_alert_data(self, alert_uuid: str) -> dict:
        """Fetch enriched alert data and context documents via MCP resources.

        Returns a dict with keys: title, severity, source_name, occurred_at,
        status, indicators, detection_rule, context_documents.
        """
        alert_json = await self.read_resource(f"calseta://alerts/{alert_uuid}")
        if not alert_json:
            raise ValueError(f"Empty response for alert {alert_uuid}")
        try:
            alert_data = json.loads(alert_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON for alert {alert_uuid}: {exc}") from exc

        context_json = await self.read_resource(f"calseta://alerts/{alert_uuid}/context")
        try:
            context_data = json.loads(context_json) if context_json else []
        except json.JSONDecodeError:
            logger.warning("Invalid JSON in context for alert %s, skipping", alert_uuid)
            context_data = []

        # Merge context documents into the alert data dict
        if isinstance(context_data, dict):
            context_docs = context_data.get("context_documents", [])
        elif isinstance(context_data, list):
            context_docs = context_data
        else:
            context_docs = []

        return {
            "title": alert_data.get("title", "Unknown"),
            "severity": alert_data.get("severity", "Unknown"),
            "source_name": alert_data.get("source_name", "unknown"),
            "occurred_at": alert_data.get("occurred_at", ""),
            "status": alert_data.get("status", "Open"),
            "indicators": alert_data.get("indicators", []),
            "detection_rule": alert_data.get("detection_rule"),
            "context_documents": context_docs,
        }

    @traceable(name="post_finding", run_type="tool")
    async def post_finding(
        self,
        alert_uuid: str,
        summary: str,
        confidence: str,
        recommended_action: str | None,
        evidence: dict | None,
        agent_name: str = "calseta-security-analyst",
    ) -> str:
        """Post an analysis finding to an alert via MCP tool.

        Returns the finding_id from Calseta.
        """
        arguments: dict = {
            "alert_uuid": alert_uuid,
            "summary": summary,
            "confidence": confidence,
            "agent_name": agent_name,
        }
        if recommended_action:
            arguments["recommended_action"] = recommended_action
        if evidence:
            arguments["evidence"] = json.dumps(evidence)

        result_json = await self.call_tool("post_alert_finding", arguments)
        result = json.loads(result_json)

        if "error" in result:
            raise RuntimeError(f"Failed to post finding: {result['error']}")

        return result["finding_id"]

    async def search_open_alerts(self, page: int = 1, page_size: int = 50) -> dict:
        """Search for open, enriched alerts ready for analysis."""
        result_json = await self.call_tool("search_alerts", {
            "status": "Open",
            "is_enriched": True,
            "enrichment_status": "Enriched",
            "page": page,
            "page_size": page_size,
        })
        return json.loads(result_json)
