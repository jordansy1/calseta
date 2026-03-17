"""System prompt and dynamic prompt builder for alert analysis."""

from __future__ import annotations

import json

try:
    from langsmith import traceable
except ImportError:
    def traceable(**kwargs):  # type: ignore[misc]
        def decorator(fn):  # type: ignore[no-untyped-def]
            return fn
        return decorator

SYSTEM_PROMPT = """You are a senior Security Operations Center (SOC) analyst. You are given an enriched security alert with threat intelligence data from multiple providers.

Your task:
1. Assess whether this alert is a TRUE POSITIVE, FALSE POSITIVE, or NEEDS MORE INVESTIGATION
2. Explain what the indicators mean in the context of this specific alert
3. Identify relevant MITRE ATT&CK tactics and techniques if applicable
4. Recommend concrete, actionable next steps for the SOC team

Be specific and evidence-based. Reference the enrichment data to support your conclusions. Do not speculate beyond what the data shows.

Your response MUST end with a JSON block in this exact format:

```json
{
  "assessment": "true_positive | false_positive | needs_investigation",
  "confidence": "low | medium | high",
  "risk_score": 0-100,
  "recommended_action": "Concrete next steps for the SOC analyst",
  "indicator_verdicts": {
    "<indicator_value>": {
      "verdict": "Malicious | Suspicious | Benign",
      "reasoning": "Brief explanation"
    }
  },
  "mitre_tactics": ["Tactic name if applicable"],
  "mitre_techniques": ["Txxxx - Technique name if applicable"],
  "key_observations": ["One observation per line"]
}
```"""


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
