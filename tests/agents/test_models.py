"""Tests for the AnalysisResult dataclass."""

from __future__ import annotations

from agents.security_analyst.models import AnalysisResult


class TestAnalysisResult:
    def test_create_with_all_fields(self) -> None:
        result = AnalysisResult(
            summary="## Analysis\nThis is a test.",
            confidence="high",
            assessment="true_positive",
            risk_score=85,
            recommended_action="Block the IP.",
            evidence={"risk_score": 85},
            raw_response="full response text",
            cost_usd=0.042,
        )
        assert result.confidence == "high"
        assert result.evidence == {"risk_score": 85}

    def test_create_with_none_optionals(self) -> None:
        result = AnalysisResult(
            summary="Analysis text",
            confidence="low",
            assessment="needs_investigation",
            risk_score=None,
            recommended_action=None,
            evidence=None,
            raw_response="response",
            cost_usd=None,
        )
        assert result.recommended_action is None
        assert result.evidence is None
        assert result.cost_usd is None
