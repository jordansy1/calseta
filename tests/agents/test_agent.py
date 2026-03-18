"""Tests for the agent orchestrator."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from agents.security_analyst.agent import analyze_alert
from agents.security_analyst.config import Config
from agents.security_analyst.models import AnalysisResult

_TEST_CONFIG = Config(api_key="cai_testkey123456789012345678")

_SAMPLE_ALERT_DATA = {
    "title": "Suspicious login",
    "severity": "High",
    "source_name": "google_workspace",
    "occurred_at": "2026-03-14T09:55:00Z",
    "status": "Open",
    "indicators": [
        {
            "type": "ip",
            "value": "185.220.101.34",
            "malice": "Malicious",
            "enrichment_results": {
                "virustotal": {"extracted": {"malicious_count": 14}},
            },
        }
    ],
    "detection_rule": None,
    "context_documents": [],
}

_SAMPLE_RESULT = AnalysisResult(
    summary="This is malicious.",
    confidence="high",
    assessment="true_positive",
    recommended_action="Block the IP",
    evidence={"risk_score": 85},
    raw_response="full response",
    cost_usd=0.04,
)


class TestAnalyzeAlert:
    @pytest.mark.asyncio
    async def test_full_pipeline(self) -> None:
        """analyze_alert fetches data, builds prompt, analyzes, and posts finding."""
        mock_mcp = AsyncMock()
        mock_mcp.fetch_alert_data = AsyncMock(return_value=_SAMPLE_ALERT_DATA)
        mock_mcp.post_finding = AsyncMock(return_value="finding-uuid-123")

        with patch(
            "agents.security_analyst.agent.analyze_llm",
            return_value=_SAMPLE_RESULT,
        ):
            result = await analyze_alert("alert-uuid-abc", _TEST_CONFIG, mock_mcp)

        assert result.assessment == "true_positive"
        assert result.confidence == "high"

        # Verify MCP calls
        mock_mcp.fetch_alert_data.assert_awaited_once_with("alert-uuid-abc")
        mock_mcp.post_finding.assert_awaited_once()
        post_args = mock_mcp.post_finding.call_args
        assert post_args[1]["alert_uuid"] == "alert-uuid-abc"
        assert post_args[1]["summary"] == "This is malicious."
        assert post_args[1]["confidence"] == "high"
        assert post_args[1]["evidence"] == {"risk_score": 85}

    @pytest.mark.asyncio
    async def test_dry_run_skips_llm_and_post(self) -> None:
        """In dry run mode, fetch + prompt happen, but no LLM call or finding post."""
        mock_mcp = AsyncMock()
        mock_mcp.fetch_alert_data = AsyncMock(return_value=_SAMPLE_ALERT_DATA)

        result = await analyze_alert(
            "alert-uuid-abc", _TEST_CONFIG, mock_mcp, dry_run=True
        )

        assert result is None
        mock_mcp.fetch_alert_data.assert_awaited_once()
        mock_mcp.post_finding.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_finding_post_failure_does_not_crash(self) -> None:
        """If posting the finding fails, the result is still returned."""
        mock_mcp = AsyncMock()
        mock_mcp.fetch_alert_data = AsyncMock(return_value=_SAMPLE_ALERT_DATA)
        mock_mcp.post_finding = AsyncMock(side_effect=RuntimeError("MCP error"))

        with patch(
            "agents.security_analyst.agent.analyze_llm",
            return_value=_SAMPLE_RESULT,
        ):
            result = await analyze_alert("alert-uuid-abc", _TEST_CONFIG, mock_mcp)

        # Result is still returned despite post failure
        assert result is not None
        assert result.assessment == "true_positive"
