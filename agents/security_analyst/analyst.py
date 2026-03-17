"""Claude Code subprocess caller and response parser.

Invokes Claude Code in non-interactive mode (--print) and parses the
two-layer JSON response: outer Claude Code wrapper → inner analysis JSON block.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess

from agents.security_analyst.config import Config
from agents.security_analyst.models import AnalysisResult

logger = logging.getLogger(__name__)

try:
    from langsmith import traceable
except ImportError:
    def traceable(**kwargs):  # type: ignore[misc]
        def decorator(fn):  # type: ignore[no-untyped-def]
            return fn
        return decorator

_JSON_BLOCK_RE = re.compile(r"```json\s*\n(.*?)\n\s*```", re.DOTALL)
_LARGE_PROMPT_THRESHOLD = 7000


class ClaudeCodeError(Exception):
    """Raised when Claude Code fails or returns an error."""


class ClaudeCodeNotFoundError(ClaudeCodeError):
    """Raised when the claude CLI is not installed."""

    def __init__(self) -> None:
        super().__init__(
            "Claude Code CLI not found. Install it: https://docs.anthropic.com/en/docs/claude-code"
        )


@traceable(name="analyze_llm", run_type="llm")
def analyze(system_prompt: str, user_prompt: str, config: Config) -> AnalysisResult:
    """Call Claude Code and parse the response into an AnalysisResult.

    This is a blocking function — call via asyncio.to_thread() from async code.
    """
    if shutil.which("claude") is None:
        raise ClaudeCodeNotFoundError()

    cmd = [
        "claude", "--print", "--output-format", "json",
        "--system-prompt", system_prompt,
        "--model", config.model,
    ]

    stdin_input = None
    if len(user_prompt) > _LARGE_PROMPT_THRESHOLD:
        # Pass via stdin to avoid OS command-line length limits.
        # claude --print reads from stdin when -p is omitted.
        stdin_input = user_prompt
    else:
        cmd.extend(["-p", user_prompt])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout,
            input=stdin_input,
        )
    except subprocess.TimeoutExpired as exc:
        raise ClaudeCodeError(f"Claude Code timed out after {config.timeout}s") from exc

    if proc.returncode != 0:
        raise ClaudeCodeError(
            f"Claude Code exited with code {proc.returncode}: {proc.stderr.strip()}"
        )

    return parse_claude_response(proc.stdout)


def parse_claude_response(stdout: str) -> AnalysisResult:
    """Parse Claude Code JSON output and extract the analysis.

    Two-layer parsing:
    1. Parse the Claude Code JSON wrapper (type, result, cost_usd, is_error)
    2. Extract the fenced ```json block from the model's response text
    """
    try:
        wrapper = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ClaudeCodeError(f"Failed to parse Claude Code output as JSON: {exc}") from exc

    if wrapper.get("is_error"):
        raise ClaudeCodeError(str(wrapper.get("result", "Unknown error")))

    result_text = wrapper.get("result", "")
    cost_usd = wrapper.get("cost_usd")

    # Extract the JSON evidence block
    match = _JSON_BLOCK_RE.search(result_text)
    if match:
        narrative = result_text[: match.start()].strip()
        try:
            evidence = json.loads(match.group(1))
        except json.JSONDecodeError:
            logger.warning("Failed to parse JSON block from Claude response — using narrative only")
            evidence = None
            narrative = result_text.strip()
    else:
        logger.warning("No JSON block found in Claude response — using narrative only")
        evidence = None
        narrative = result_text.strip()

    # Extract fields from evidence, with defaults for fallback
    if evidence:
        confidence = evidence.get("confidence", "medium")
        assessment = evidence.get("assessment", "needs_investigation")
        recommended_action = evidence.get("recommended_action")
    else:
        confidence = "medium"
        assessment = "needs_investigation"
        recommended_action = None

    return AnalysisResult(
        summary=narrative,
        confidence=confidence,
        assessment=assessment,
        recommended_action=recommended_action,
        evidence=evidence,
        raw_response=result_text,
        cost_usd=cost_usd,
    )
