"""Tests for the prompt builder."""

from __future__ import annotations

from agents.security_analyst.prompt import SYSTEM_PROMPT, build_analysis_prompt


class TestSystemPrompt:
    def test_system_prompt_contains_json_instruction(self) -> None:
        """System prompt must instruct the model to output a JSON block."""
        assert "```json" in SYSTEM_PROMPT
        assert "assessment" in SYSTEM_PROMPT
        assert "confidence" in SYSTEM_PROMPT

    def test_system_prompt_mentions_soc_analyst_role(self) -> None:
        assert "SOC" in SYSTEM_PROMPT or "security analyst" in SYSTEM_PROMPT.lower()


class TestBuildAnalysisPrompt:
    def test_builds_prompt_from_alert_data(self) -> None:
        """build_analysis_prompt returns (system_prompt, user_prompt) tuple."""
        data = {
            "title": "Suspicious login from TOR exit node",
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
                        "virustotal": {
                            "extracted": {"malicious_count": 14, "reputation": -42}
                        },
                        "abuseipdb": {
                            "extracted": {"abuse_confidence_score": 100}
                        },
                    },
                }
            ],
            "detection_rule": None,
            "context_documents": [],
        }
        system_prompt, user_prompt = build_analysis_prompt(data)
        assert system_prompt == SYSTEM_PROMPT
        assert "Suspicious login from TOR exit node" in user_prompt
        assert "185.220.101.34" in user_prompt
        assert "Malicious" in user_prompt

    def test_includes_detection_rule_when_present(self) -> None:
        data = {
            "title": "Test alert",
            "severity": "Medium",
            "source_name": "sentinel",
            "occurred_at": "2026-03-14T10:00:00Z",
            "status": "Open",
            "indicators": [],
            "detection_rule": {
                "name": "TOR Exit Node Login",
                "documentation": "Detects logins from known TOR exit nodes.",
                "mitre_tactics": ["Initial Access"],
                "mitre_techniques": ["T1078"],
            },
            "context_documents": [],
        }
        _, user_prompt = build_analysis_prompt(data)
        assert "TOR Exit Node Login" in user_prompt
        assert "Initial Access" in user_prompt

    def test_includes_context_documents_when_present(self) -> None:
        data = {
            "title": "Test alert",
            "severity": "Low",
            "source_name": "elastic",
            "occurred_at": "2026-03-14T10:00:00Z",
            "status": "Open",
            "indicators": [],
            "detection_rule": None,
            "context_documents": [
                {"title": "Login Investigation Runbook", "content": "Step 1: Check geo..."}
            ],
        }
        _, user_prompt = build_analysis_prompt(data)
        assert "Login Investigation Runbook" in user_prompt

    def test_handles_empty_indicators(self) -> None:
        data = {
            "title": "Test",
            "severity": "Low",
            "source_name": "generic",
            "occurred_at": "2026-03-14T10:00:00Z",
            "status": "Open",
            "indicators": [],
            "detection_rule": None,
            "context_documents": [],
        }
        system_prompt, user_prompt = build_analysis_prompt(data)
        assert isinstance(user_prompt, str)
        assert len(user_prompt) > 0
