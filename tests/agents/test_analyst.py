"""Tests for the Claude Code subprocess caller and response parser."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from agents.security_analyst.analyst import (
    ClaudeCodeError,
    ClaudeCodeNotFoundError,
    analyze,
    parse_claude_response,
)
from agents.security_analyst.config import Config

# ---------------------------------------------------------------------------
# parse_claude_response tests
# ---------------------------------------------------------------------------

_VALID_EVIDENCE = {
    "assessment": "true_positive",
    "confidence": "high",
    "risk_score": 85,
    "recommended_action": "Block the IP",
    "indicator_verdicts": {},
    "mitre_tactics": ["Initial Access"],
    "mitre_techniques": ["T1078 - Valid Accounts"],
    "key_observations": ["TOR exit node"],
}


def _make_claude_output(result_text: str, cost: float = 0.04) -> str:
    return json.dumps({
        "type": "result",
        "subtype": "success",
        "result": result_text,
        "is_error": False,
        "cost_usd": cost,
        "session_id": "test-session",
        "model": "claude-sonnet-4-6-20250514",
    })


class TestParseClaudeResponse:
    def test_extracts_narrative_and_evidence(self) -> None:
        narrative = "## Analysis\nThis is a true positive.\n\n"
        json_block = f"```json\n{json.dumps(_VALID_EVIDENCE)}\n```"
        stdout = _make_claude_output(narrative + json_block)

        result = parse_claude_response(stdout)
        assert "true positive" in result.summary
        assert result.confidence == "high"
        assert result.assessment == "true_positive"
        assert result.evidence is not None
        assert result.evidence["risk_score"] == 85
        assert result.cost_usd == 0.04

    def test_handles_missing_json_block_gracefully(self) -> None:
        """When model doesn't produce JSON block, summary is full text, evidence is None."""
        stdout = _make_claude_output("This alert looks suspicious but I need more data.")
        result = parse_claude_response(stdout)
        assert "suspicious" in result.summary
        assert result.evidence is None
        assert result.confidence == "medium"  # default when extraction fails
        assert result.assessment == "needs_investigation"  # default

    def test_handles_is_error_true(self) -> None:
        output = json.dumps({
            "type": "result",
            "subtype": "error",
            "result": "Rate limited",
            "is_error": True,
            "cost_usd": 0,
        })
        with pytest.raises(ClaudeCodeError, match="Rate limited"):
            parse_claude_response(output)

    def test_handles_malformed_json_block(self) -> None:
        """Malformed JSON inside the block → fallback to narrative-only."""
        text = "Analysis here\n```json\n{invalid json\n```"
        stdout = _make_claude_output(text)
        result = parse_claude_response(stdout)
        assert result.evidence is None
        assert "Analysis here" in result.summary

    def test_handles_invalid_stdout_json(self) -> None:
        with pytest.raises(ClaudeCodeError, match="Failed to parse"):
            parse_claude_response("not json at all")


# ---------------------------------------------------------------------------
# analyze() tests (subprocess mocking)
# ---------------------------------------------------------------------------

class TestAnalyze:
    def test_claude_not_installed_raises(self) -> None:
        with patch("shutil.which", return_value=None), pytest.raises(ClaudeCodeNotFoundError):
            analyze("system", "user", Config(api_key="cai_testkey123456789012345678"))

    def test_successful_analysis(self) -> None:
        narrative = "This is malicious.\n"
        json_block = f"```json\n{json.dumps(_VALID_EVIDENCE)}\n```"
        mock_stdout = _make_claude_output(narrative + json_block)

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = mock_stdout
        mock_proc.stderr = ""

        with (
            patch("shutil.which", return_value="/usr/bin/claude"),
            patch("subprocess.run", return_value=mock_proc),
        ):
            config = Config(api_key="cai_testkey123456789012345678")
            result = analyze("system prompt", "user prompt", config)

        assert result.assessment == "true_positive"
        assert result.confidence == "high"

    def test_subprocess_timeout_raises(self) -> None:
        import subprocess
        with (
            patch("shutil.which", return_value="/usr/bin/claude"),
            patch("subprocess.run", side_effect=subprocess.TimeoutExpired("claude", 120)),
            pytest.raises(ClaudeCodeError, match="timed out"),
        ):
            analyze("system", "user", Config(api_key="cai_testkey123456789012345678"))

    def test_nonzero_exit_code_raises(self) -> None:
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "Permission denied"

        with (
            patch("shutil.which", return_value="/usr/bin/claude"),
            patch("subprocess.run", return_value=mock_proc),
            pytest.raises(ClaudeCodeError, match="Permission denied"),
        ):
            analyze("system", "user", Config(api_key="cai_testkey123456789012345678"))

    def test_large_prompt_uses_stdin(self) -> None:
        """Prompts > 7000 chars should be piped via stdin, not -p flag."""
        large_prompt = "x" * 8000
        narrative = "Short analysis.\n"
        json_block = f"```json\n{json.dumps(_VALID_EVIDENCE)}\n```"
        mock_stdout = _make_claude_output(narrative + json_block)

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = mock_stdout
        mock_proc.stderr = ""

        with (
            patch("shutil.which", return_value="/usr/bin/claude"),
            patch("subprocess.run", return_value=mock_proc) as mock_run,
        ):
            analyze("system prompt", large_prompt, Config(api_key="cai_testkey123456789012345678"))

        call_args = mock_run.call_args
        cmd = call_args[0][0]
        # Should NOT contain -p flag for large prompts
        assert "-p" not in cmd
        # Should pass input via stdin
        assert call_args[1].get("input") == large_prompt
