"""Claude Code subprocess caller and response parser.

Invokes Claude Code in non-interactive mode (--print) with --json-schema
for guaranteed structured output. The Claude Code JSON wrapper contains:
- result: freeform narrative text (markdown)
- structured_output: schema-validated JSON with assessment fields
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess

from agents.security_analyst.config import Config
from agents.security_analyst.models import AnalysisResult
from agents.security_analyst.prompt import ANALYSIS_JSON_SCHEMA

logger = logging.getLogger(__name__)

try:
    from langsmith import traceable
except ImportError:
    from typing import Any, Callable

    def traceable(**kwargs: Any) -> Callable:  # type: ignore[misc]
        def decorator(fn: Callable) -> Callable:
            return fn
        return decorator

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
    claude_path = shutil.which("claude")
    if claude_path is None:
        raise ClaudeCodeNotFoundError()

    # NOTE: --system-prompt and --json-schema are incompatible in Claude Code CLI.
    # When both are present, --json-schema is silently ignored (no structured_output).
    # Workaround: embed system instructions at the top of the user prompt.
    combined_prompt = f"{system_prompt}\n\n---\n\n{user_prompt}"

    cmd = [
        claude_path, "--print", "--output-format", "json",
        "--model", config.model,
        "--json-schema", json.dumps(ANALYSIS_JSON_SCHEMA),
    ]

    stdin_input = None
    if len(combined_prompt) > _LARGE_PROMPT_THRESHOLD:
        stdin_input = combined_prompt
        logger.debug("Prompt too large (%d chars) — sending via stdin", len(combined_prompt))
    else:
        cmd.extend(["-p", combined_prompt])
        logger.debug("Prompt (%d chars) — sending via -p flag", len(combined_prompt))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
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
    """Parse Claude Code JSON output with structured_output.

    The Claude Code wrapper contains:
    - result: narrative text (markdown)
    - structured_output: schema-validated JSON (assessment, risk_score, etc.)
    - total_cost_usd: LLM cost
    """
    try:
        wrapper = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ClaudeCodeError(f"Failed to parse Claude Code output as JSON: {exc}") from exc

    logger.debug("Claude Code wrapper keys: %s", list(wrapper.keys()))
    logger.debug("stop_reason=%s, num_turns=%s, is_error=%s",
                 wrapper.get("stop_reason"), wrapper.get("num_turns"), wrapper.get("is_error"))

    if wrapper.get("is_error"):
        raise ClaudeCodeError(str(wrapper.get("result", "Unknown error")))

    narrative = wrapper.get("result", "").strip()
    cost_usd = wrapper.get("total_cost_usd")
    structured = wrapper.get("structured_output")
    logger.debug("structured_output type=%s, truthy=%s", type(structured).__name__, bool(structured))

    if structured and isinstance(structured, dict):
        evidence = {k: v for k, v in structured.items() if k != "narrative"}
        return AnalysisResult(
            summary=narrative,
            confidence=structured.get("confidence", "medium"),
            assessment=structured.get("assessment", "needs_investigation"),
            risk_score=structured.get("risk_score"),
            recommended_action=structured.get("recommended_action"),
            evidence=evidence,
            raw_response=narrative,
            cost_usd=cost_usd,
        )

    # Fallback if structured_output is missing
    logger.warning("No structured_output in Claude Code response — using narrative only")
    return AnalysisResult(
        summary=narrative,
        confidence="medium",
        assessment="needs_investigation",
        risk_score=None,
        recommended_action=None,
        evidence=None,
        raw_response=narrative,
        cost_usd=cost_usd,
    )
