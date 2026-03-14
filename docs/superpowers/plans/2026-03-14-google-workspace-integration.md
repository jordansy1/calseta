# Google Workspace Alert Center Integration — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect Google Workspace Alert Center to Calseta's ingest/enrich/dispatch pipeline and set up a webhook listener for Claude Code analysis testing.

**Architecture:** New `AlertSourceBase` subclass for Google Workspace, a manual fetch script that pulls alerts from the Alert Center API and POSTs them to Calseta, and a lightweight webhook listener that saves dispatched alerts for Claude Code to analyze. Enrichment uses existing built-in VirusTotal + AbuseIPDB providers (config-only).

**Tech Stack:** Python 3.12, FastAPI (existing), google-auth + google-api-python-client (fetch script), httpx (fetch script HTTP client), http.server (webhook listener)

**Spec:** `docs/superpowers/specs/2026-03-14-google-workspace-integration-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `app/integrations/sources/google_workspace.py` | AlertSourceBase subclass — validate, normalize, extract indicators from Alert Center payloads |
| `app/integrations/sources/__init__.py` | Register GoogleWorkspaceSource (2-line edit) |
| `tests/test_google_workspace_source.py` | Unit tests for the source plugin |
| `tests/fixtures/google_workspace_account_warning.json` | AccountWarning test fixture |
| `tests/fixtures/google_workspace_mail_phishing.json` | MailPhishing test fixture |
| `docs/integrations/google-workspace/api_notes.md` | API research artifact (required by Calseta convention) |
| `scripts/fetch_google_alerts.py` | Manual CLI script to pull alerts from Google and forward to Calseta |
| `scripts/alert_listener.py` | Webhook listener that saves dispatched alerts to disk |
| `.gitignore` | Add `scripts/alerts/` and `scripts/google-sa-key.json` |
| `.env` | Add `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` (user action, not code) |

---

## Chunk 1: Google Workspace Source Plugin + Tests

### Task 1: Create test fixtures

**Files:**
- Create: `tests/fixtures/google_workspace_account_warning.json`
- Create: `tests/fixtures/google_workspace_mail_phishing.json`

- [ ] **Step 1: Create AccountWarning fixture**

```json
{
  "alertId": "gw-test-001",
  "customerId": "C01234567",
  "createTime": "2026-03-14T10:00:00Z",
  "startTime": "2026-03-14T09:55:00Z",
  "type": "Suspicious login blocked",
  "source": "Google Identity",
  "data": {
    "@type": "type.googleapis.com/google.apps.alertcenter.type.AccountWarning",
    "email": "j.martinez@contoso.com",
    "loginDetails": {
      "ipAddress": "185.220.101.34",
      "loginTime": "2026-03-14T09:55:00Z"
    }
  },
  "metadata": {
    "customerId": "C01234567",
    "alertId": "gw-test-001",
    "status": "NOT_STARTED",
    "severity": "HIGH",
    "updateTime": "2026-03-14T10:00:00Z"
  }
}
```

- [ ] **Step 2: Create MailPhishing fixture**

```json
{
  "alertId": "gw-test-002",
  "customerId": "C01234567",
  "createTime": "2026-03-14T11:00:00Z",
  "startTime": "2026-03-14T10:45:00Z",
  "type": "User reported phishing",
  "source": "Gmail phishing",
  "data": {
    "@type": "type.googleapis.com/google.apps.alertcenter.type.MailPhishing",
    "domainId": {"customerPrimaryDomain": "contoso.com"},
    "maliciousEntity": {
      "entity": {"emailAddress": "attacker@evil-domain.com", "displayName": "Support Team"},
      "fromHeader": "support@evil-domain.com",
      "displayName": "IT Support"
    },
    "messages": [
      {
        "messageId": "msg-123",
        "md5HashSubject": "abc123",
        "md5HashMessageBody": "def456"
      }
    ],
    "isInternal": false
  },
  "metadata": {
    "customerId": "C01234567",
    "alertId": "gw-test-002",
    "status": "NOT_STARTED",
    "severity": "MEDIUM",
    "updateTime": "2026-03-14T11:00:00Z"
  }
}
```

- [ ] **Step 3: Commit fixtures**

```bash
git add tests/fixtures/google_workspace_account_warning.json tests/fixtures/google_workspace_mail_phishing.json
git commit -m "test: add Google Workspace Alert Center test fixtures"
```

---

### Task 2: Write failing tests for GoogleWorkspaceSource

**Files:**
- Create: `tests/test_google_workspace_source.py`

- [ ] **Step 1: Write the test file**

Follow the exact pattern from `tests/test_source_integrations.py`. Tests should cover:

```python
"""Tests for Google Workspace Alert Center source integration."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.integrations.sources.google_workspace import GoogleWorkspaceSource
from app.schemas.alert import AlertSeverity
from app.schemas.indicators import IndicatorType

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class TestGoogleWorkspaceSource:
    @pytest.fixture
    def source(self) -> GoogleWorkspaceSource:
        return GoogleWorkspaceSource()

    @pytest.fixture
    def account_warning(self) -> dict:
        return _load("google_workspace_account_warning.json")

    @pytest.fixture
    def mail_phishing(self) -> dict:
        return _load("google_workspace_mail_phishing.json")

    # --- source_name ---

    def test_source_name(self, source: GoogleWorkspaceSource) -> None:
        assert source.source_name == "google_workspace"

    def test_display_name(self, source: GoogleWorkspaceSource) -> None:
        assert source.display_name == "Google Workspace Alert Center"

    # --- validate_payload ---

    def test_validate_valid_account_warning(self, source: GoogleWorkspaceSource, account_warning: dict) -> None:
        assert source.validate_payload(account_warning) is True

    def test_validate_valid_mail_phishing(self, source: GoogleWorkspaceSource, mail_phishing: dict) -> None:
        assert source.validate_payload(mail_phishing) is True

    def test_validate_empty_dict(self, source: GoogleWorkspaceSource) -> None:
        assert source.validate_payload({}) is False

    def test_validate_missing_type(self, source: GoogleWorkspaceSource) -> None:
        assert source.validate_payload({"alertId": "abc"}) is False

    def test_validate_missing_alert_id(self, source: GoogleWorkspaceSource) -> None:
        assert source.validate_payload({"type": "Suspicious login blocked"}) is False

    # --- normalize: AccountWarning ---

    def test_normalize_title(self, source: GoogleWorkspaceSource, account_warning: dict) -> None:
        alert = source.normalize(account_warning)
        assert alert.title == "Suspicious login blocked"

    def test_normalize_severity_from_metadata(self, source: GoogleWorkspaceSource, account_warning: dict) -> None:
        alert = source.normalize(account_warning)
        assert alert.severity == AlertSeverity.HIGH

    def test_normalize_severity_missing_metadata(self, source: GoogleWorkspaceSource, account_warning: dict) -> None:
        del account_warning["metadata"]
        alert = source.normalize(account_warning)
        assert alert.severity == AlertSeverity.PENDING

    def test_normalize_occurred_at_uses_start_time(self, source: GoogleWorkspaceSource, account_warning: dict) -> None:
        alert = source.normalize(account_warning)
        assert alert.occurred_at == datetime(2026, 3, 14, 9, 55, tzinfo=UTC)

    def test_normalize_occurred_at_fallback_to_create_time(self, source: GoogleWorkspaceSource, account_warning: dict) -> None:
        del account_warning["startTime"]
        alert = source.normalize(account_warning)
        assert alert.occurred_at == datetime(2026, 3, 14, 10, 0, tzinfo=UTC)

    def test_normalize_source_name(self, source: GoogleWorkspaceSource, account_warning: dict) -> None:
        alert = source.normalize(account_warning)
        assert alert.source_name == "google_workspace"

    def test_normalize_actor_email(self, source: GoogleWorkspaceSource, account_warning: dict) -> None:
        alert = source.normalize(account_warning)
        assert alert.actor_email == "j.martinez@contoso.com"

    def test_normalize_src_ip(self, source: GoogleWorkspaceSource, account_warning: dict) -> None:
        alert = source.normalize(account_warning)
        assert alert.src_ip == "185.220.101.34"

    # --- normalize: MailPhishing ---

    def test_normalize_phishing_title(self, source: GoogleWorkspaceSource, mail_phishing: dict) -> None:
        alert = source.normalize(mail_phishing)
        assert alert.title == "User reported phishing"

    def test_normalize_phishing_severity(self, source: GoogleWorkspaceSource, mail_phishing: dict) -> None:
        alert = source.normalize(mail_phishing)
        assert alert.severity == AlertSeverity.MEDIUM

    def test_normalize_phishing_email_from(self, source: GoogleWorkspaceSource, mail_phishing: dict) -> None:
        alert = source.normalize(mail_phishing)
        assert alert.email_from == "support@evil-domain.com"

    # --- extract_indicators: AccountWarning ---

    def test_extract_indicators_account_warning(self, source: GoogleWorkspaceSource, account_warning: dict) -> None:
        indicators = source.extract_indicators(account_warning)
        types = {(i.type, i.value) for i in indicators}
        assert (IndicatorType.IP, "185.220.101.34") in types
        assert (IndicatorType.ACCOUNT, "j.martinez@contoso.com") in types

    def test_extract_indicators_no_login_details(self, source: GoogleWorkspaceSource, account_warning: dict) -> None:
        del account_warning["data"]["loginDetails"]
        indicators = source.extract_indicators(account_warning)
        types = {(i.type, i.value) for i in indicators}
        assert (IndicatorType.ACCOUNT, "j.martinez@contoso.com") in types
        # No IP without loginDetails
        assert not any(i.type == IndicatorType.IP for i in indicators)

    # --- extract_indicators: MailPhishing ---

    def test_extract_indicators_mail_phishing(self, source: GoogleWorkspaceSource, mail_phishing: dict) -> None:
        indicators = source.extract_indicators(mail_phishing)
        types = {(i.type, i.value) for i in indicators}
        assert (IndicatorType.EMAIL, "support@evil-domain.com") in types
        assert (IndicatorType.ACCOUNT, "attacker@evil-domain.com") in types

    # --- extract_indicators: empty/invalid ---

    def test_extract_indicators_empty_data(self, source: GoogleWorkspaceSource) -> None:
        result = source.extract_indicators({"alertId": "x", "type": "Unknown", "data": {}})
        assert isinstance(result, list)

    # --- extract_detection_rule_ref ---

    def test_extract_detection_rule_ref(self, source: GoogleWorkspaceSource, account_warning: dict) -> None:
        ref = source.extract_detection_rule_ref(account_warning)
        assert ref == "gw-test-001"

    # --- verify_webhook_signature ---

    def test_verify_webhook_signature_always_true(self, source: GoogleWorkspaceSource) -> None:
        assert source.verify_webhook_signature({}, b"") is True

    # --- documented_extractions ---

    def test_documented_extractions_not_empty(self, source: GoogleWorkspaceSource) -> None:
        extractions = source.documented_extractions()
        assert len(extractions) > 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec api pytest tests/test_google_workspace_source.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.integrations.sources.google_workspace'`

- [ ] **Step 3: Commit failing tests**

```bash
git add tests/test_google_workspace_source.py
git commit -m "test: add failing tests for Google Workspace source plugin"
```

---

### Task 3: Implement GoogleWorkspaceSource

**Files:**
- Create: `app/integrations/sources/google_workspace.py`

- [ ] **Step 1: Write the source plugin**

Follow the Sentinel pattern (`app/integrations/sources/sentinel.py`). Key implementation details:

```python
"""
Google Workspace Alert Center source integration.

Normalizes Alert Center alert payloads to the Calseta agent-native schema.
Alerts are fetched via a local polling script and POSTed to
/v1/ingest/google_workspace. No webhook signature verification — this is
a polled source with API key auth.

Field mapping reference: docs/integrations/google-workspace/api_notes.md
"""

from __future__ import annotations

from datetime import datetime

import structlog

from app.integrations.sources.base import AlertSourceBase, SourcePluginExtraction
from app.schemas.alert import AlertSeverity, CalsetaAlert
from app.schemas.indicators import IndicatorExtract, IndicatorType

logger = structlog.get_logger(__name__)

_SEVERITY_MAP: dict[str, AlertSeverity] = {
    "HIGH": AlertSeverity.HIGH,
    "MEDIUM": AlertSeverity.MEDIUM,
    "LOW": AlertSeverity.LOW,
}


class GoogleWorkspaceSource(AlertSourceBase):
    """Alert source plugin for Google Workspace Alert Center."""

    source_name = "google_workspace"
    display_name = "Google Workspace Alert Center"

    def validate_payload(self, raw: dict) -> bool:
        try:
            return bool(raw.get("alertId") and raw.get("type"))
        except Exception:
            return False

    def normalize(self, raw: dict) -> CalsetaAlert:
        title = raw.get("type", "Unknown Google Workspace Alert")

        # Severity lives in metadata.severity, NOT top-level
        metadata = raw.get("metadata") or {}
        raw_severity = metadata.get("severity", "")
        severity = _SEVERITY_MAP.get(raw_severity, AlertSeverity.PENDING)

        # Prefer startTime (when event occurred) over createTime (when alert was created)
        occurred_at_str = raw.get("startTime") or raw.get("createTime")
        if occurred_at_str:
            try:
                occurred_at = datetime.fromisoformat(occurred_at_str.replace("Z", "+00:00"))
            except ValueError:
                occurred_at = datetime.now().astimezone()
        else:
            occurred_at = datetime.now().astimezone()

        source_label = raw.get("source", "Google Workspace")
        description = f"{source_label}: {title}"

        data = raw.get("data") or {}

        # Normalized fields for Pass 2 extraction
        actor_email = data.get("email")
        src_ip = None
        email_from = None

        login_details = data.get("loginDetails")
        if isinstance(login_details, dict):
            src_ip = login_details.get("ipAddress")

        malicious_entity = data.get("maliciousEntity")
        if isinstance(malicious_entity, dict):
            email_from = malicious_entity.get("fromHeader")

        tags = [raw.get("type", ""), raw.get("source", "")]
        tags = [t for t in tags if t]

        return CalsetaAlert(
            title=title,
            severity=severity,
            occurred_at=occurred_at,
            source_name=self.source_name,
            description=description,
            actor_email=actor_email,
            src_ip=src_ip,
            email_from=email_from,
            tags=tags,
        )

    def extract_indicators(self, raw: dict) -> list[IndicatorExtract]:
        indicators: list[IndicatorExtract] = []
        seen: set[tuple[str, str]] = set()
        data = raw.get("data") or {}

        def _add(itype: IndicatorType, val: str, field: str) -> None:
            key = (itype.value, val)
            if val and key not in seen:
                seen.add(key)
                indicators.append(IndicatorExtract(type=itype, value=val, source_field=field))

        # AccountWarning fields
        if email := data.get("email"):
            _add(IndicatorType.ACCOUNT, email, "data.email")

        login_details = data.get("loginDetails")
        if isinstance(login_details, dict):
            if ip := login_details.get("ipAddress"):
                _add(IndicatorType.IP, ip, "data.loginDetails.ipAddress")

        # MailPhishing fields
        malicious_entity = data.get("maliciousEntity")
        if isinstance(malicious_entity, dict):
            if from_header := malicious_entity.get("fromHeader"):
                if "@" in from_header:
                    _add(IndicatorType.EMAIL, from_header, "data.maliciousEntity.fromHeader")

            entity = malicious_entity.get("entity")
            if isinstance(entity, dict):
                if entity_email := entity.get("emailAddress"):
                    _add(IndicatorType.ACCOUNT, entity_email, "data.maliciousEntity.entity.emailAddress")

        return indicators

    def extract_detection_rule_ref(self, raw: dict) -> str | None:
        return raw.get("alertId")

    def verify_webhook_signature(self, headers: dict[str, str], raw_body: bytes) -> bool:
        # Polled source — no webhook signature. Debug-level because this is intentional.
        logger.debug("google_workspace_polled_source_no_signature")
        return True

    def documented_extractions(self) -> list[SourcePluginExtraction]:
        _e = SourcePluginExtraction
        return [
            _e("data.email", "account", "AccountWarning: user email"),
            _e("data.loginDetails.ipAddress", "ip", "AccountWarning: login IP"),
            _e("data.maliciousEntity.fromHeader", "email", "MailPhishing: sender email"),
            _e("data.maliciousEntity.entity.emailAddress", "account", "MailPhishing: attacker email"),
        ]
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `docker compose exec api pytest tests/test_google_workspace_source.py -v`
Expected: All tests PASS

- [ ] **Step 3: Commit implementation**

```bash
git add app/integrations/sources/google_workspace.py
git commit -m "feat: add Google Workspace Alert Center source plugin"
```

---

### Task 4: Register the source plugin

**Files:**
- Modify: `app/integrations/sources/__init__.py`

- [ ] **Step 1: Add import and registration**

Add after the existing `GenericSource` registration:

```python
from app.integrations.sources.google_workspace import GoogleWorkspaceSource
source_registry.register(GoogleWorkspaceSource())
```

- [ ] **Step 2: Verify registration**

Run: `docker compose exec api python -c "from app.integrations.sources import source_registry; print([s.source_name for s in source_registry.list_all()])"`
Expected: `['sentinel', 'elastic', 'splunk', 'generic', 'google_workspace']`

- [ ] **Step 3: Run full test suite to catch regressions**

Run: `docker compose exec api pytest tests/test_source_registry.py tests/test_source_integrations.py tests/test_google_workspace_source.py -v`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add app/integrations/sources/__init__.py
git commit -m "feat: register Google Workspace source in plugin registry"
```

---

### Task 5: Test ingest endpoint with synthetic payload

- [ ] **Step 1: Rebuild the API container** (picks up new source file)

```bash
cd "Code Projects/everett_young/calseta" && docker compose up -d --build api worker
```

- [ ] **Step 2: POST a synthetic alert**

```bash
curl -s -X POST http://localhost:8000/v1/ingest/google_workspace \
  -H "Authorization: Bearer cai_sJC7buH2tJ6XgAjvexDm1bDRpCET8M-7Cfysl0Ld8-4" \
  -H "Content-Type: application/json" \
  -d '{
    "alertId": "test-001",
    "type": "Suspicious login blocked",
    "source": "Google Identity",
    "createTime": "2026-03-14T10:00:00Z",
    "startTime": "2026-03-14T09:55:00Z",
    "metadata": {"severity": "HIGH", "status": "NOT_STARTED"},
    "data": {
      "@type": "type.googleapis.com/google.apps.alertcenter.type.AccountWarning",
      "email": "j.martinez@contoso.com",
      "loginDetails": {"ipAddress": "185.220.101.34", "loginTime": "2026-03-14T09:55:00Z"}
    }
  }' | python -m json.tool
```

Expected: `202 Accepted` with `{"data": {"alert_uuid": "...", "status": "queued"}}`

- [ ] **Step 3: Verify alert was created**

```bash
curl -s -H "Authorization: Bearer cai_sJC7buH2tJ6XgAjvexDm1bDRpCET8M-7Cfysl0Ld8-4" \
  http://localhost:8000/v1/alerts?source_name=google_workspace | python -m json.tool
```

Expected: One alert with `title: "Suspicious login blocked"`, `severity: "High"`, `source_name: "google_workspace"`

- [ ] **Step 4: Commit (no files changed — this was a manual verification step)**

---

## Chunk 2: Enrichment Configuration + Webhook Listener + Fetch Script

### Task 6: Configure VirusTotal + AbuseIPDB enrichment

- [ ] **Step 1: Add API keys to .env**

Edit `.env` in the calseta directory. Add your real keys:
```
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

- [ ] **Step 2: Restart services**

```bash
cd "Code Projects/everett_young/calseta" && docker compose restart api worker
```

- [ ] **Step 3: Verify providers are configured**

```bash
curl -s -H "Authorization: Bearer cai_sJC7buH2tJ6XgAjvexDm1bDRpCET8M-7Cfysl0Ld8-4" \
  http://localhost:8000/v1/enrichment-providers | python -m json.tool
```

Expected: `virustotal` and `abuseipdb` both show `is_active: true`

---

### Task 7: Create the webhook listener

**Files:**
- Create: `scripts/alert_listener.py`

- [ ] **Step 1: Write the listener**

Based on `scripts/mock_agent.py` pattern, but saves files to disk:

```python
#!/usr/bin/env python3
"""
Webhook listener for Claude Code security analysis testing.

Receives enriched alert payloads from Calseta's agent dispatch system,
saves them to scripts/alerts/ as JSON files, and prints a summary.

Usage:
    python3 scripts/alert_listener.py
    PORT=8888 python3 scripts/alert_listener.py

Register webhook in Calseta:
    curl -X POST http://localhost:8000/v1/agents \
      -H "Authorization: Bearer $KEY" \
      -H "Content-Type: application/json" \
      -d '{"name": "claude-code-analyst", "endpoint_url": "http://host.docker.internal:9998/webhook"}'
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from pathlib import Path
import json
import os


ALERTS_DIR = Path(__file__).parent / "alerts"


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}

        # Extract alert info for filename and summary
        alert = body.get("alert", {})
        alert_uuid = alert.get("uuid", "unknown")
        title = alert.get("title", "Unknown")
        severity = alert.get("severity", "Unknown")
        indicators = body.get("indicators", [])
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save to disk
        filename = f"{timestamp}_{alert_uuid}.json"
        filepath = ALERTS_DIR / filename
        filepath.write_text(json.dumps(body, indent=2))

        # Print summary
        print(f"[{timestamp}] Alert: {title} | Severity: {severity} | Indicators: {len(indicators)} | Saved: {filename}")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress default HTTP logging — our print statements are sufficient
        pass


if __name__ == "__main__":
    ALERTS_DIR.mkdir(exist_ok=True)
    port = int(os.environ.get("PORT", 9998))
    print(f"Alert listener on http://0.0.0.0:{port}")
    print(f"Saving alerts to {ALERTS_DIR.resolve()}")
    print("Waiting for webhooks...")
    HTTPServer(("0.0.0.0", port), WebhookHandler).serve_forever()
```

- [ ] **Step 2: Commit**

```bash
git add scripts/alert_listener.py
git commit -m "feat: add webhook listener for Claude Code analysis testing"
```

---

### Task 8: Create the fetch script

**Files:**
- Create: `scripts/fetch_google_alerts.py`

- [ ] **Step 1: Write the fetch script**

```python
#!/usr/bin/env python3
"""
Fetch Google Workspace Alert Center alerts and forward to Calseta.

Manual trigger — fetches alerts for a specified time range, POSTs each
to Calseta's ingest endpoint. Calseta handles deduplication via fingerprinting.

Prerequisites:
  - pip install google-auth google-api-python-client httpx
  - Service account JSON with domain-wide delegation
  - Alert Center API enabled in GCP Console
  - Service account client ID added to Google Admin domain-wide delegation
    with scope: https://www.googleapis.com/auth/apps.alerts

Usage:
    python scripts/fetch_google_alerts.py --admin-email admin@yourdomain.com --hours 24
    python scripts/fetch_google_alerts.py --admin-email admin@yourdomain.com --since 2026-03-13T00:00:00Z
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import httpx
from google.oauth2 import service_account
from googleapiclient.discovery import build


SCOPES = ["https://www.googleapis.com/auth/apps.alerts"]


def build_service(credentials_path: str, admin_email: str):
    """Build an Alert Center API service with delegated credentials."""
    creds = service_account.Credentials.from_service_account_file(
        credentials_path, scopes=SCOPES
    )
    delegated = creds.with_subject(admin_email)
    return build("alertcenter", "v1beta1", credentials=delegated)


def fetch_alerts(service, since: str) -> list[dict]:
    """Fetch alerts created since the given ISO 8601 timestamp."""
    alerts = []
    request = service.alerts().list(
        filter=f'createTime >= "{since}"',
        orderBy="createTime asc",
        pageSize=100,
    )
    while request is not None:
        response = request.execute()
        alerts.extend(response.get("alerts", []))
        request = service.alerts().list_next(request, response)
    return alerts


def forward_to_calseta(alert: dict, calseta_url: str, api_key: str) -> dict:
    """POST a single alert to Calseta's ingest endpoint."""
    with httpx.Client(timeout=30) as client:
        resp = client.post(
            f"{calseta_url}/v1/ingest/google_workspace",
            json=alert,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        return resp.json()


def main():
    parser = argparse.ArgumentParser(
        description="Fetch Google Workspace Alert Center alerts and forward to Calseta."
    )
    parser.add_argument("--credentials", default="scripts/google-sa-key.json",
                        help="Path to service account JSON (default: scripts/google-sa-key.json)")
    parser.add_argument("--admin-email", required=True,
                        help="Admin email for domain-wide delegation")

    time_group = parser.add_mutually_exclusive_group()
    time_group.add_argument("--hours", type=int, default=24,
                            help="How many hours back to look (default: 24)")
    time_group.add_argument("--since",
                            help="ISO 8601 timestamp to fetch from (e.g. 2026-03-13T00:00:00Z)")

    parser.add_argument("--calseta-url", default="http://localhost:8000",
                        help="Calseta API base URL (default: http://localhost:8000)")
    parser.add_argument("--calseta-key", default=os.environ.get("CALSETA_API_KEY", ""),
                        help="Calseta API key (or set CALSETA_API_KEY env var)")
    args = parser.parse_args()

    if not args.calseta_key:
        print("Error: --calseta-key or CALSETA_API_KEY env var required", file=sys.stderr)
        sys.exit(1)

    # Determine time range
    if args.since:
        since = args.since
    else:
        since = (datetime.now(timezone.utc) - timedelta(hours=args.hours)).isoformat()

    print(f"Fetching alerts since {since}")

    # Build Google API service
    try:
        service = build_service(args.credentials, args.admin_email)
    except Exception as e:
        print(f"Auth error: {e}", file=sys.stderr)
        sys.exit(1)

    # Fetch alerts
    try:
        alerts = fetch_alerts(service, since)
    except Exception as e:
        print(f"Google API error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(alerts)} alert(s)")

    # Forward to Calseta
    forwarded = 0
    duplicates = 0
    errors = 0
    for alert in alerts:
        try:
            result = forward_to_calseta(alert, args.calseta_url, args.calseta_key)
            status = result.get("data", {}).get("status", "")
            if status == "deduplicated":
                duplicates += 1
            else:
                forwarded += 1
            alert_id = alert.get("alertId", "?")
            print(f"  {alert_id}: {status}")
        except Exception as e:
            errors += 1
            alert_id = alert.get("alertId", "?")
            print(f"  {alert_id}: ERROR — {e}", file=sys.stderr)

    print(f"\nDone. Forwarded: {forwarded}, Duplicates: {duplicates}, Errors: {errors}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Commit**

```bash
git add scripts/fetch_google_alerts.py
git commit -m "feat: add manual Google Alert Center fetch script"
```

---

### Task 9: Update .gitignore

**Files:**
- Modify: `.gitignore`

- [ ] **Step 1: Add entries**

Append to `.gitignore`:

```
# Google Workspace fetch script
scripts/alerts/
scripts/google-sa-key.json
```

- [ ] **Step 2: Commit**

```bash
git add .gitignore
git commit -m "chore: gitignore alert listener output and Google SA key"
```

---

### Task 10: Write API notes doc

**Files:**
- Create: `docs/integrations/google-workspace/api_notes.md`

- [ ] **Step 1: Write API research artifact**

Required by Calseta convention before any integration code ships. Document:
- Alert Center API v1beta1 base URL and auth requirements
- Alert resource fields (with severity in metadata, not top-level)
- Key data types: AccountWarning, MailPhishing, UserChanges, StateSponsoredAttack
- Rate limits (default quota: 5 QPS)
- Pagination via `pageToken` / `nextPageToken`
- Filter syntax: `createTime >= "ISO8601"`
- Known edge cases: severity field location, polymorphic `data` field

- [ ] **Step 2: Commit**

```bash
git add docs/integrations/google-workspace/api_notes.md
git commit -m "docs: add Google Workspace Alert Center API notes"
```

---

## Chunk 3: End-to-End Verification

### Task 11: Register webhook agent and test full pipeline

- [ ] **Step 1: Start the alert listener**

In a separate terminal:
```bash
cd "Code Projects/everett_young/calseta"
python scripts/alert_listener.py
```

- [ ] **Step 2: Register the agent webhook**

```bash
curl -s -X POST http://localhost:8000/v1/agents \
  -H "Authorization: Bearer cai_sJC7buH2tJ6XgAjvexDm1bDRpCET8M-7Cfysl0Ld8-4" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "claude-code-analyst",
    "description": "Local webhook listener for Claude Code security analysis testing",
    "endpoint_url": "http://host.docker.internal:9998/webhook",
    "trigger_on_severities": ["High", "Critical"],
    "is_active": true
  }' | python -m json.tool
```

- [ ] **Step 3: Ingest a synthetic Google Workspace alert**

```bash
curl -s -X POST http://localhost:8000/v1/ingest/google_workspace \
  -H "Authorization: Bearer cai_sJC7buH2tJ6XgAjvexDm1bDRpCET8M-7Cfysl0Ld8-4" \
  -H "Content-Type: application/json" \
  -d '{
    "alertId": "e2e-test-001",
    "type": "Suspicious login blocked",
    "source": "Google Identity",
    "createTime": "2026-03-14T14:00:00Z",
    "startTime": "2026-03-14T13:55:00Z",
    "metadata": {"severity": "HIGH", "status": "NOT_STARTED"},
    "data": {
      "@type": "type.googleapis.com/google.apps.alertcenter.type.AccountWarning",
      "email": "j.martinez@contoso.com",
      "loginDetails": {"ipAddress": "185.220.101.34", "loginTime": "2026-03-14T13:55:00Z"}
    }
  }' | python -m json.tool
```

- [ ] **Step 4: Verify enrichment completed**

Wait ~10 seconds for the worker to process, then:
```bash
curl -s -H "Authorization: Bearer cai_sJC7buH2tJ6XgAjvexDm1bDRpCET8M-7Cfysl0Ld8-4" \
  "http://localhost:8000/v1/alerts?source_name=google_workspace" | python -m json.tool
```

Expected: `enrichment_status: "Enriched"`, `is_enriched: true`

- [ ] **Step 5: Verify webhook was received**

Check the alert listener terminal — should show:
```
[20260314_...] Alert: Suspicious login blocked | Severity: High | Indicators: 2 | Saved: ...json
```

Check `scripts/alerts/` for the saved JSON file.

- [ ] **Step 6: Analyze alert and post finding (Claude Code)**

Read the saved alert JSON, analyze it, and POST a finding back:
```bash
curl -s -X POST http://localhost:8000/v1/alerts/{ALERT_UUID}/findings \
  -H "Authorization: Bearer cai_sJC7buH2tJ6XgAjvexDm1bDRpCET8M-7Cfysl0Ld8-4" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "claude-code-analyst",
    "summary": "Analysis of suspicious login...",
    "confidence": "high",
    "recommended_action": "Verify with user, check for credential compromise"
  }'
```

- [ ] **Step 7: Verify finding appears on the alert**

```bash
curl -s -H "Authorization: Bearer cai_sJC7buH2tJ6XgAjvexDm1bDRpCET8M-7Cfysl0Ld8-4" \
  "http://localhost:8000/v1/alerts/{ALERT_UUID}/findings" | python -m json.tool
```

Expected: Finding with `agent_name: "claude-code-analyst"` and your summary.

---

## Summary

| Chunk | Tasks | Description |
|-------|-------|-------------|
| 1 | Tasks 1-5 | Source plugin: fixtures → tests → implementation → registration → smoke test |
| 2 | Tasks 6-10 | Enrichment config + listener + fetch script + gitignore + API docs |
| 3 | Task 11 | End-to-end: register agent → ingest → enrich → dispatch → analyze → finding |
