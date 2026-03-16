"""Data models for the security analyst agent."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AnalysisResult:
    """Result of Claude Code analysis of an enriched alert."""

    summary: str
    """Narrative analysis in markdown."""

    confidence: str
    """One of: 'low', 'medium', 'high'."""

    assessment: str
    """One of: 'true_positive', 'false_positive', 'needs_investigation'."""

    recommended_action: str | None
    """Concrete next steps for the SOC analyst."""

    evidence: dict | None
    """Structured evidence dict; None if JSON extraction failed."""

    raw_response: str
    """Full Claude Code response text (for debugging)."""

    cost_usd: float | None
    """LLM cost from Claude Code JSON output, if available."""
