# Security Analyst Agent — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone CLI agent that reads enriched alerts from Calseta via MCP, analyzes them with Claude Code, and posts structured findings back.

**Architecture:** Async orchestrator with single event loop. MCP SDK for SSE client (read resources, call tools). Claude Code subprocess for LLM analysis. LangSmith `@traceable` for per-step tracing. All code lives in `agents/security_analyst/` — independent from the Calseta application.

**Tech Stack:** Python 3.12+, `mcp` SDK (SSE client), `langsmith`, `httpx`, `python-dotenv`, `argparse`

**Spec:** `docs/superpowers/specs/2026-03-16-security-analyst-agent-design.md`

---

## File Map

| File | Responsibility | New/Modify |
|---|---|---|
| `app/mcp/tools/alerts.py` | Add `evidence` parameter to `post_alert_finding` | Modify |
| `tests/test_mcp/test_mcp_tools.py` | Test evidence parameter | Modify |
| `agents/security_analyst/__init__.py` | Package marker | Create |
| `agents/security_analyst/__main__.py` | CLI entry point, `asyncio.run()` | Create |
| `agents/security_analyst/config.py` | Env var settings via `python-dotenv` | Create |
| `agents/security_analyst/models.py` | `AnalysisResult` dataclass | Create |
| `agents/security_analyst/prompt.py` | System prompt constant + `build_analysis_prompt()` | Create |
| `agents/security_analyst/analyst.py` | Claude Code subprocess + two-layer JSON parsing | Create |
| `agents/security_analyst/mcp_client.py` | SSE connect, read resources, call tools | Create |
| `agents/security_analyst/agent.py` | Async orchestrator `analyze_alert()` | Create |
| `agents/security_analyst/requirements.txt` | Dependencies | Create |
| `agents/security_analyst/.env.example` | Example env vars | Create |
| `tests/agents/__init__.py` | Test package marker | Create |
| `tests/agents/test_models.py` | AnalysisResult tests | Create |
| `tests/agents/test_prompt.py` | Prompt builder tests | Create |
| `tests/agents/test_analyst.py` | Claude Code parsing tests | Create |
| `tests/agents/test_agent.py` | Orchestrator tests | Create |

---

## Chunk 1: MCP Tool Prerequisite — Add Evidence Parameter

This is a Calseta platform change that must ship before the agent can post findings with evidence.

### Task 1: Add `evidence` parameter to `post_alert_finding`

**Files:**
- Modify: `app/mcp/tools/alerts.py:44-96`
- Modify: `tests/test_mcp/test_mcp_tools.py`

- [ ] **Step 1: Write failing test for evidence parameter**

Add to `tests/test_mcp/test_mcp_tools.py` at the end of the file:

```python
class TestPostAlertFindingEvidence:
    """Tests for the evidence parameter on post_alert_finding."""

    async def test_post_finding_with_evidence_json(self) -> None:
        """post_alert_finding parses evidence JSON string into dict."""
        alert = _mock_alert()
        session_ctx, mock_session = _patch_session()
        mock_repo = MagicMock()
        mock_repo.get_by_uuid = AsyncMock(return_value=alert)
        mock_repo.add_finding = AsyncMock(return_value=alert)

        evidence_dict = {"assessment": "true_positive", "risk_score": 85}
        evidence_json = json.dumps(evidence_dict)

        with (
            patch("app.mcp.tools.alerts.AsyncSessionLocal", session_ctx),
            patch("app.mcp.tools.alerts.check_scope", _scope_pass()),
            patch("app.mcp.tools.alerts.AlertRepository", return_value=mock_repo),
            patch("app.mcp.tools.alerts.ActivityEventService"),
        ):
            from app.mcp.tools.alerts import post_alert_finding
            result = await post_alert_finding(
                alert_uuid=str(alert.uuid),
                summary="Test finding",
                confidence="high",
                ctx=_mock_ctx(),
                evidence=evidence_json,
            )

        data = json.loads(result)
        assert "finding_id" in data

        # Verify the finding dict passed to add_finding contains parsed evidence
        call_args = mock_repo.add_finding.call_args
        finding_dict = call_args[0][1]  # second positional arg
        assert finding_dict["evidence"] == evidence_dict

    async def test_post_finding_without_evidence_defaults_to_none(self) -> None:
        """post_alert_finding without evidence keeps evidence=None (backwards compat)."""
        alert = _mock_alert()
        session_ctx, mock_session = _patch_session()
        mock_repo = MagicMock()
        mock_repo.get_by_uuid = AsyncMock(return_value=alert)
        mock_repo.add_finding = AsyncMock(return_value=alert)

        with (
            patch("app.mcp.tools.alerts.AsyncSessionLocal", session_ctx),
            patch("app.mcp.tools.alerts.check_scope", _scope_pass()),
            patch("app.mcp.tools.alerts.AlertRepository", return_value=mock_repo),
            patch("app.mcp.tools.alerts.ActivityEventService"),
        ):
            from app.mcp.tools.alerts import post_alert_finding
            result = await post_alert_finding(
                alert_uuid=str(alert.uuid),
                summary="Test finding",
                confidence="high",
                ctx=_mock_ctx(),
            )

        call_args = mock_repo.add_finding.call_args
        finding_dict = call_args[0][1]
        assert finding_dict["evidence"] is None

    async def test_post_finding_with_invalid_evidence_json(self) -> None:
        """post_alert_finding rejects malformed evidence JSON."""
        alert = _mock_alert()
        session_ctx, mock_session = _patch_session()
        mock_repo = MagicMock()
        mock_repo.get_by_uuid = AsyncMock(return_value=alert)

        with (
            patch("app.mcp.tools.alerts.AsyncSessionLocal", session_ctx),
            patch("app.mcp.tools.alerts.check_scope", _scope_pass()),
            patch("app.mcp.tools.alerts.AlertRepository", return_value=mock_repo),
        ):
            from app.mcp.tools.alerts import post_alert_finding
            result = await post_alert_finding(
                alert_uuid=str(alert.uuid),
                summary="Test finding",
                confidence="high",
                ctx=_mock_ctx(),
                evidence="not valid json {{{",
            )

        data = json.loads(result)
        assert "error" in data
        assert "evidence" in data["error"].lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd agents/security_analyst/../../ && python -m pytest tests/test_mcp/test_mcp_tools.py::TestPostAlertFindingEvidence -v`
Expected: FAIL — `evidence` parameter not accepted

- [ ] **Step 3: Implement evidence parameter**

In `app/mcp/tools/alerts.py`, modify the `post_alert_finding` function signature and body:

```python
@mcp_server.tool()
async def post_alert_finding(
    alert_uuid: str,
    summary: str,
    confidence: str,
    ctx: Context,
    agent_name: str = "mcp-agent",
    recommended_action: str | None = None,
    evidence: str | None = None,
) -> str:
    """Post an agent analysis finding to an alert.

    Args:
        alert_uuid: UUID of the alert to attach the finding to.
        summary: Free-text analysis summary (what was found, why it matters).
        confidence: Confidence level — one of: "low", "medium", "high".
        agent_name: Name identifying the agent posting this finding.
        recommended_action: Optional suggested next step for the SOC analyst.
        evidence: Optional JSON string containing structured evidence data.
            Will be parsed to a dict and stored alongside the finding.

    Returns:
        JSON with the created finding ID and posted_at timestamp.
    """
    try:
        parsed_uuid = _uuid.UUID(alert_uuid)
    except ValueError:
        return json.dumps({"error": f"Invalid UUID: {alert_uuid}"})

    if confidence not in _VALID_CONFIDENCES:
        return json.dumps({
            "error": f"Invalid confidence '{confidence}'. Must be one of: {_VALID_CONFIDENCES}"
        })

    # Parse evidence JSON if provided
    parsed_evidence = None
    if evidence is not None:
        try:
            parsed_evidence = json.loads(evidence)
        except json.JSONDecodeError as exc:
            return json.dumps({
                "error": f"Invalid evidence JSON: {exc}"
            })

    async with AsyncSessionLocal() as session:
        scope_err = await check_scope(ctx, session, "alerts:write")
        if scope_err:
            return scope_err

        repo = AlertRepository(session)
        alert = await repo.get_by_uuid(parsed_uuid)
        if alert is None:
            return json.dumps({"error": f"Alert not found: {alert_uuid}"})

        now = datetime.now(UTC)
        finding_id = str(_uuid.uuid4())
        finding = {
            "id": finding_id,
            "agent_name": agent_name,
            "summary": summary,
            "confidence": confidence,
            "recommended_action": recommended_action,
            "evidence": parsed_evidence,
            "posted_at": now.isoformat(),
        }

        await repo.add_finding(alert, finding)

        activity_svc = ActivityEventService(session)
        await activity_svc.write(
            ActivityEventType.ALERT_FINDING_ADDED,
            actor_type="mcp",
            actor_key_prefix=_resolve_client_id(ctx),
            alert_id=alert.id,
            references={"finding_id": finding_id, "agent_name": agent_name},
        )

        await session.commit()

        return json.dumps({
            "finding_id": finding_id,
            "alert_uuid": alert_uuid,
            "posted_at": now.isoformat(),
        })
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_mcp/test_mcp_tools.py::TestPostAlertFindingEvidence -v`
Expected: 3 tests PASS

- [ ] **Step 5: Run full MCP tool test suite for regressions**

Run: `python -m pytest tests/test_mcp/ -v`
Expected: All existing tests still PASS

- [ ] **Step 6: Commit**

```bash
git add app/mcp/tools/alerts.py tests/test_mcp/test_mcp_tools.py
git commit -m "feat: add evidence parameter to post_alert_finding MCP tool"
```

---

## Chunk 2: Agent Foundation — Config, Models, and Project Scaffolding

### Task 2: Create agent package scaffolding and config

**Files:**
- Create: `agents/security_analyst/__init__.py`
- Create: `agents/security_analyst/config.py`
- Create: `agents/security_analyst/models.py`
- Create: `agents/security_analyst/requirements.txt`
- Create: `agents/security_analyst/.env.example`
- Create: `tests/agents/__init__.py`
- Create: `tests/agents/test_models.py`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p agents/security_analyst
mkdir -p tests/agents
```

- [ ] **Step 2: Create `agents/security_analyst/__init__.py`**

```python
"""Calseta Security Analyst Agent — standalone CLI agent for alert analysis."""
```

- [ ] **Step 3: Create `agents/security_analyst/requirements.txt`**

```
mcp>=1.9,<2
langsmith>=0.3,<1
httpx>=0.28.0,<1
python-dotenv>=1.0.0,<2
```

- [ ] **Step 4: Create `agents/security_analyst/.env.example`**

```bash
# Required — Calseta MCP API key (cai_ prefix)
CALSETA_API_KEY=cai_your_api_key_here

# Optional — MCP server URL (default: http://localhost:8001)
# CALSETA_MCP_URL=http://localhost:8001

# Optional — Claude Code model (default: sonnet). Valid: sonnet, opus, haiku
# ANALYST_MODEL=sonnet

# Optional — Subprocess timeout in seconds (default: 120)
# ANALYST_TIMEOUT=120

# Optional — LangSmith tracing (disabled if LANGCHAIN_API_KEY is unset)
# LANGCHAIN_API_KEY=lsv2_your_key_here
# LANGCHAIN_PROJECT=calseta-security-analyst
# LANGCHAIN_TRACING_V2=true
```

- [ ] **Step 5: Write test for AnalysisResult dataclass**

Create `tests/agents/__init__.py`:
```python
```

Create `tests/agents/test_models.py`:
```python
"""Tests for the AnalysisResult dataclass."""

from __future__ import annotations

from agents.security_analyst.models import AnalysisResult


class TestAnalysisResult:
    def test_create_with_all_fields(self) -> None:
        result = AnalysisResult(
            summary="## Analysis\nThis is a test.",
            confidence="high",
            assessment="true_positive",
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
            recommended_action=None,
            evidence=None,
            raw_response="response",
            cost_usd=None,
        )
        assert result.recommended_action is None
        assert result.evidence is None
        assert result.cost_usd is None
```

- [ ] **Step 6: Run test to verify it fails**

Run: `python -m pytest tests/agents/test_models.py -v`
Expected: FAIL — module not found

- [ ] **Step 7: Create `agents/security_analyst/models.py`**

```python
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
```

- [ ] **Step 8: Create `agents/security_analyst/config.py`**

```python
"""Configuration for the security analyst agent.

All settings are loaded from environment variables or a .env file
in the agents/security_analyst/ directory.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the agent's own directory
_AGENT_DIR = Path(__file__).parent
load_dotenv(_AGENT_DIR / ".env")


@dataclass
class Config:
    """Agent configuration — all values from env vars with sensible defaults."""

    mcp_url: str = field(
        default_factory=lambda: os.getenv("CALSETA_MCP_URL", "http://localhost:8001")
    )
    api_key: str = field(
        default_factory=lambda: os.environ["CALSETA_API_KEY"]
    )
    model: str = field(
        default_factory=lambda: os.getenv("ANALYST_MODEL", "sonnet")
    )
    timeout: int = field(
        default_factory=lambda: int(os.getenv("ANALYST_TIMEOUT", "120"))
    )

    def __post_init__(self) -> None:
        if not self.api_key.startswith("cai_"):
            raise ValueError("CALSETA_API_KEY must start with 'cai_'")
        if self.model not in ("sonnet", "opus", "haiku"):
            raise ValueError(f"ANALYST_MODEL must be sonnet, opus, or haiku — got '{self.model}'")
```

- [ ] **Step 9: Run tests to verify they pass**

Run: `CALSETA_API_KEY=cai_test python -m pytest tests/agents/test_models.py -v`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add agents/security_analyst/ tests/agents/
git commit -m "feat: scaffold security analyst agent with config and models"
```

---

### Task 3: Prompt builder

**Files:**
- Create: `agents/security_analyst/prompt.py`
- Create: `tests/agents/test_prompt.py`

- [ ] **Step 1: Write failing tests for prompt builder**

Create `tests/agents/test_prompt.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/agents/test_prompt.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Implement prompt.py**

Create `agents/security_analyst/prompt.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/agents/test_prompt.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add agents/security_analyst/prompt.py tests/agents/test_prompt.py
git commit -m "feat: add system prompt and dynamic prompt builder for analyst agent"
```

---

### Task 4: Claude Code subprocess caller and response parser

**Files:**
- Create: `agents/security_analyst/analyst.py`
- Create: `tests/agents/test_analyst.py`

- [ ] **Step 1: Write failing tests for analyst.py**

Create `tests/agents/test_analyst.py`:

```python
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
        with patch("shutil.which", return_value=None):
            with pytest.raises(ClaudeCodeNotFoundError):
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
            result = analyze("system prompt", "user prompt", Config(api_key="cai_testkey123456789012345678"))

        assert result.assessment == "true_positive"
        assert result.confidence == "high"

    def test_subprocess_timeout_raises(self) -> None:
        import subprocess
        with (
            patch("shutil.which", return_value="/usr/bin/claude"),
            patch("subprocess.run", side_effect=subprocess.TimeoutExpired("claude", 120)),
        ):
            with pytest.raises(ClaudeCodeError, match="timed out"):
                analyze("system", "user", Config(api_key="cai_testkey123456789012345678"))

    def test_nonzero_exit_code_raises(self) -> None:
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "Permission denied"

        with (
            patch("shutil.which", return_value="/usr/bin/claude"),
            patch("subprocess.run", return_value=mock_proc),
        ):
            with pytest.raises(ClaudeCodeError, match="Permission denied"):
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/agents/test_analyst.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Implement analyst.py**

Create `agents/security_analyst/analyst.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/agents/test_analyst.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add agents/security_analyst/analyst.py tests/agents/test_analyst.py
git commit -m "feat: add Claude Code subprocess caller with two-layer JSON parsing"
```

---

## Chunk 3: MCP Client and Orchestrator

### Task 5: MCP client — connect, read resources, call tools

**Files:**
- Create: `agents/security_analyst/mcp_client.py`

This module wraps the `mcp` SDK's SSE client. Unit testing the MCP client directly requires a running MCP server, so we test it indirectly through the orchestrator (Task 6) with mocks and validate it end-to-end in the integration test (Task 8).

- [ ] **Step 1: Create `agents/security_analyst/mcp_client.py`**

```python
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
        """Call an MCP tool and return its text result."""
        assert self._session is not None, "MCPClient not connected"
        result = await self._session.call_tool(name, arguments)
        if result.content:
            return result.content[0].text or ""
        return ""

    @traceable(name="fetch_alert_data", run_type="retriever")
    async def fetch_alert_data(self, alert_uuid: str) -> dict:
        """Fetch enriched alert data and context documents via MCP resources.

        Returns a dict with keys: title, severity, source_name, occurred_at,
        status, indicators, detection_rule, context_documents.
        """
        alert_json = await self.read_resource(f"calseta://alerts/{alert_uuid}")
        alert_data = json.loads(alert_json)

        context_json = await self.read_resource(f"calseta://alerts/{alert_uuid}/context")
        context_data = json.loads(context_json) if context_json else []

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
```

- [ ] **Step 2: Commit**

```bash
git add agents/security_analyst/mcp_client.py
git commit -m "feat: add MCP SSE client for alert data access and finding submission"
```

---

### Task 6: Orchestrator and CLI entry point

**Files:**
- Create: `agents/security_analyst/agent.py`
- Create: `agents/security_analyst/__main__.py`
- Create: `tests/agents/test_agent.py`

- [ ] **Step 1: Write failing tests for orchestrator**

Create `tests/agents/test_agent.py`:

```python
"""Tests for the agent orchestrator."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/agents/test_agent.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Implement agent.py**

Create `agents/security_analyst/agent.py`:

```python
"""Orchestrator — ties MCP data access, prompt building, LLM analysis, and finding submission together."""

from __future__ import annotations

import asyncio
import logging

from agents.security_analyst.analyst import analyze as analyze_llm
from agents.security_analyst.config import Config
from agents.security_analyst.mcp_client import MCPClient
from agents.security_analyst.models import AnalysisResult
from agents.security_analyst.prompt import build_analysis_prompt

logger = logging.getLogger(__name__)

try:
    from langsmith import traceable
except ImportError:
    # LangSmith not installed — provide a no-op decorator
    def traceable(**kwargs):  # type: ignore[misc]
        def decorator(fn):  # type: ignore[no-untyped-def]
            return fn
        return decorator


@traceable(name="analyze_alert", run_type="chain")
async def analyze_alert(
    alert_uuid: str,
    config: Config,
    mcp: MCPClient,
    *,
    dry_run: bool = False,
) -> AnalysisResult | None:
    """Run the full analysis pipeline for a single alert.

    Steps:
    1. Fetch enriched alert data via MCP
    2. Build analysis prompt
    3. Call Claude Code (unless dry_run)
    4. Post finding back to Calseta (unless dry_run)
    """
    # Step 1: Fetch alert data
    logger.info("Fetching alert data", extra={"alert_uuid": alert_uuid})
    data = await mcp.fetch_alert_data(alert_uuid)

    # Step 2: Build prompt
    system_prompt, user_prompt = build_analysis_prompt(data)

    if dry_run:
        print(f"\n{'='*60}")
        print("DRY RUN — Prompt that would be sent to Claude Code:")
        print(f"{'='*60}")
        print(f"\n--- SYSTEM PROMPT ---\n{system_prompt[:500]}...")
        print(f"\n--- USER PROMPT ---\n{user_prompt}")
        print(f"\n{'='*60}")
        return None

    # Step 3: Call Claude Code (blocking — offloaded to thread pool)
    logger.info("Calling Claude Code", extra={"model": config.model})
    result = await asyncio.to_thread(analyze_llm, system_prompt, user_prompt, config)

    # Step 4: Post finding back to Calseta
    try:
        finding_id = await mcp.post_finding(
            alert_uuid=alert_uuid,
            summary=result.summary,
            confidence=result.confidence,
            recommended_action=result.recommended_action,
            evidence=result.evidence,
        )
        logger.info("Finding posted", extra={"finding_id": finding_id, "alert_uuid": alert_uuid})
    except Exception:
        logger.exception("Failed to post finding — analysis still available in stdout")

    return result


async def run_single(alert_uuid: str, config: Config, *, dry_run: bool = False) -> None:
    """Analyze a single alert."""
    async with MCPClient(config) as mcp:
        result = await analyze_alert(alert_uuid, config, mcp, dry_run=dry_run)
        if result:
            _print_result(alert_uuid, result)


async def run_batch(config: Config, *, max_alerts: int = 10) -> None:
    """Analyze all open, enriched alerts up to max_alerts."""
    async with MCPClient(config) as mcp:
        processed = 0
        posted = 0
        skipped = 0
        page = 1

        while processed < max_alerts:
            search_result = await mcp.search_open_alerts(page=page, page_size=50)
            alerts = search_result.get("alerts", [])
            if not alerts:
                break

            for alert_info in alerts:
                if processed >= max_alerts:
                    break

                alert_uuid = alert_info["uuid"]
                processed += 1

                try:
                    result = await analyze_alert(alert_uuid, config, mcp)
                    if result:
                        _print_result(alert_uuid, result)
                        posted += 1
                except Exception:
                    logger.exception("Error analyzing alert", extra={"alert_uuid": alert_uuid})
                    skipped += 1

            page += 1

        print(f"\nProcessed {processed} alerts: {posted} findings posted, {skipped} skipped (errors)")


def _print_result(alert_uuid: str, result: AnalysisResult) -> None:
    """Print analysis result summary to stdout."""
    print(f"\n--- Alert: {alert_uuid} ---")
    print(f"Assessment: {result.assessment}")
    print(f"Confidence: {result.confidence}")
    if result.recommended_action:
        print(f"Recommended: {result.recommended_action}")
    if result.cost_usd is not None:
        print(f"Cost: ${result.cost_usd:.4f}")
    print(f"\n{result.summary[:500]}")
    if len(result.summary) > 500:
        print("... (truncated)")
```

- [ ] **Step 4: Implement `__main__.py`**

Create `agents/security_analyst/__main__.py`:

```python
"""CLI entry point: python -m agents.security_analyst"""

from __future__ import annotations

import argparse
import asyncio
import logging
import shutil
import sys

from agents.security_analyst.agent import run_batch, run_single
from agents.security_analyst.config import Config


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calseta Security Analyst Agent — analyze enriched alerts with Claude Code"
    )
    parser.add_argument("--alert-uuid", help="UUID of a specific alert to analyze")
    parser.add_argument("--all-open", action="store_true", help="Analyze all open, enriched alerts")
    parser.add_argument("--max-alerts", type=int, default=10, help="Max alerts in batch mode (default: 10)")
    parser.add_argument("--dry-run", action="store_true", help="Fetch data and build prompt, but don't call LLM")
    parser.add_argument("--model", help="Override Claude Code model (sonnet, opus, haiku)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    # Validate arguments
    if not args.alert_uuid and not args.all_open:
        parser.error("Either --alert-uuid or --all-open is required")

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Check Claude Code is installed (fail fast)
    if not args.dry_run and shutil.which("claude") is None:
        print("ERROR: Claude Code CLI not found. Install: https://docs.anthropic.com/en/docs/claude-code", file=sys.stderr)
        sys.exit(1)

    # Load config
    try:
        config = Config()
    except (KeyError, ValueError) as exc:
        print(f"ERROR: Configuration error: {exc}", file=sys.stderr)
        print("See agents/security_analyst/.env.example for required variables.", file=sys.stderr)
        sys.exit(1)

    # Override model if specified (re-validate via __post_init__)
    if args.model:
        config.model = args.model
        config.__post_init__()

    # Run
    if args.alert_uuid:
        asyncio.run(run_single(args.alert_uuid, config, dry_run=args.dry_run))
    else:
        asyncio.run(run_batch(config, max_alerts=args.max_alerts))


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/agents/test_agent.py -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add agents/security_analyst/agent.py agents/security_analyst/__main__.py tests/agents/test_agent.py
git commit -m "feat: add async orchestrator and CLI entry point for security analyst agent"
```

---

## Chunk 4: Integration Testing and Final Validation

### Task 7: Dry run smoke test

Requires Calseta running (`docker compose up`) with at least one enriched alert.

**Files:** None (manual validation)

- [ ] **Step 1: Ensure Calseta is running**

Run: `cd agents/security_analyst/../.. && docker compose ps`
Expected: `api`, `worker`, `mcp`, `db` all running

- [ ] **Step 2: Set up agent env vars**

```bash
cd agents/security_analyst
cp .env.example .env
# Edit .env: set CALSETA_API_KEY to a valid cai_ key
```

- [ ] **Step 3: Install agent dependencies**

```bash
pip install -r requirements.txt
```

- [ ] **Step 4: Run dry-run against an existing alert**

Run: `cd ../.. && python -m agents.security_analyst --alert-uuid <uuid-of-enriched-alert> --dry-run -v`

Expected: Prints system prompt + user prompt with alert data, indicators, and enrichment results. No LLM call. No finding posted.

- [ ] **Step 5: Run with Claude Code (live test)**

Run: `python -m agents.security_analyst --alert-uuid <uuid-of-enriched-alert> -v`

Expected: Fetches alert data → calls Claude Code → prints analysis → posts finding to Calseta. Verify finding appears via: `curl -H "Authorization: Bearer cai_..." http://localhost:8000/v1/alerts/<uuid>`

### Task 8: Run all tests

- [ ] **Step 1: Run the full agent test suite**

Run: `python -m pytest tests/agents/ -v`
Expected: All tests PASS

- [ ] **Step 2: Run MCP tool tests to confirm no regressions**

Run: `python -m pytest tests/test_mcp/ -v`
Expected: All tests PASS (including new evidence tests)

- [ ] **Step 3: Final commit if any changes needed**

```bash
git add -A
git commit -m "test: complete security analyst agent test suite"
```
