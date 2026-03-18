"""System prompt and dynamic prompt builder for alert analysis."""

from __future__ import annotations

import json

try:
    from langsmith import traceable
except ImportError:
    from typing import Any
    from collections.abc import Callable

    def traceable(**kwargs: Any) -> Callable:  # type: ignore[misc]
        def decorator(fn: Callable) -> Callable:
            return fn
        return decorator

SYSTEM_PROMPT = """You are a senior Security Operations Center (SOC) analyst. You are given an enriched security alert with threat intelligence data from multiple providers.

Your task:
1. Assess whether this alert is a TRUE POSITIVE, FALSE POSITIVE, or NEEDS MORE INVESTIGATION
2. Explain what the indicators mean in the context of this specific alert
3. Identify relevant MITRE ATT&CK tactics and techniques if applicable
4. Recommend concrete, actionable next steps for the SOC team

Be specific and evidence-based. Reference the enrichment data to support your conclusions. Do not speculate beyond what the data shows.

Write a detailed narrative analysis in markdown. The structured assessment fields (assessment, confidence, risk_score, etc.) will be extracted automatically — focus on the quality of your analysis."""


# JSON schema enforced via Claude Code --json-schema flag.
# This guarantees structured output — no more regex extraction.
ANALYSIS_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "narrative": {
            "type": "string",
            "description": "Full markdown-formatted SOC analysis including indicator analysis, runbook-guided investigation steps, and response recommendations.",
        },
        "assessment": {
            "type": "string",
            "enum": ["true_positive", "false_positive", "needs_investigation"],
        },
        "confidence": {
            "type": "string",
            "enum": ["low", "medium", "high"],
        },
        "risk_score": {
            "type": "integer",
            "minimum": 0,
            "maximum": 100,
            "description": "Overall risk score: 0 (benign) to 100 (critical active threat).",
        },
        "recommended_action": {
            "type": "string",
            "description": "Concrete next steps for the SOC analyst.",
        },
        "indicator_verdicts": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "properties": {
                    "verdict": {
                        "type": "string",
                        "enum": ["Malicious", "Suspicious", "Benign"],
                    },
                    "reasoning": {"type": "string"},
                },
                "required": ["verdict", "reasoning"],
            },
            "description": "Per-indicator verdict keyed by indicator value.",
        },
        "mitre_tactics": {
            "type": "array",
            "items": {"type": "string"},
        },
        "mitre_techniques": {
            "type": "array",
            "items": {"type": "string"},
        },
        "key_observations": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Key findings, one observation per item.",
        },
    },
    "required": [
        "narrative",
        "assessment",
        "confidence",
        "risk_score",
        "recommended_action",
        "indicator_verdicts",
        "mitre_tactics",
        "mitre_techniques",
        "key_observations",
    ],
}


@traceable(name="build_analysis_prompt", run_type="prompt")
def build_analysis_prompt(data: dict) -> tuple[str, str]:
    """Build (system_prompt, user_prompt) from enriched alert data.

    Args:
        data: Dict with keys: title, severity, source_name, occurred_at,
              status, indicators, detection_rule, context_documents.

    Returns:
        Tuple of (system_prompt, user_prompt).
    """
    sections: list[str] = []

    # Alert metadata
    sections.append(f"# Alert: {data['title']}")
    sections.append(f"- **Severity:** {data['severity']}")
    sections.append(f"- **Source:** {data['source_name']}")
    sections.append(f"- **Occurred at:** {data['occurred_at']}")
    sections.append(f"- **Status:** {data['status']}")

    # Indicators with enrichment
    indicators = data.get("indicators", [])
    if indicators:
        sections.append("\n## Indicators")
        for ind in indicators:
            sections.append(f"\n### {ind['type'].upper()}: `{ind['value']}`")
            sections.append(f"- **Malice verdict:** {ind.get('malice', 'Pending')}")
            enrichment = ind.get("enrichment_results", {})
            if enrichment:
                sections.append("- **Enrichment data:**")
                for provider, pdata in enrichment.items():
                    extracted = pdata.get("extracted", {})
                    if extracted:
                        sections.append(f"  - **{provider}:** {json.dumps(extracted)}")
    else:
        sections.append("\n## Indicators\nNo indicators extracted for this alert.")

    # Detection rule
    rule = data.get("detection_rule")
    if rule:
        sections.append(f"\n## Detection Rule: {rule['name']}")
        if rule.get("documentation"):
            sections.append(f"{rule['documentation']}")
        tactics = rule.get("mitre_tactics", [])
        techniques = rule.get("mitre_techniques", [])
        if tactics:
            sections.append(f"- **MITRE Tactics:** {', '.join(tactics)}")
        if techniques:
            sections.append(f"- **MITRE Techniques:** {', '.join(techniques)}")

    # Context documents
    docs = data.get("context_documents", [])
    if docs:
        sections.append("\n## Reference Documents")
        for doc in docs:
            sections.append(f"\n### {doc['title']}")
            sections.append(doc.get("content", ""))

    user_prompt = "\n".join(sections)
    return SYSTEM_PROMPT, user_prompt
