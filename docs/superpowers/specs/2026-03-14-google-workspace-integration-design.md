# Google Workspace Alert Center Integration + Agent Testing Pipeline

**Date:** 2026-03-14
**Status:** Draft
**Author:** Jordan / Claude Code

---

## Goal

Set up a local end-to-end testing pipeline: Google Workspace Alert Center alerts flow into Calseta, get enriched by VirusTotal and AbuseIPDB, dispatch to a webhook listener, and Claude Code analyzes + posts findings back via the REST API.

## Components

Three independent pieces connected through Calseta's existing pipeline:

```
Google Alert Center API
  │
  ▼
scripts/poll_google_alerts.py  (local poller, runs on host)
  │  POST /v1/ingest/google_workspace
  ▼
Calseta API (localhost:8000)
  │  normalize → extract indicators → enqueue enrichment
  ▼
Worker (enrichment queue)
  │  VirusTotal + AbuseIPDB enrich extracted IPs/domains/hashes
  ▼
Worker (dispatch queue)
  │  POST to registered webhook
  ▼
scripts/alert_listener.py  (localhost:9998)
  │  saves JSON to scripts/alerts/
  ▼
Claude Code reads alert → analyzes → POST /v1/alerts/{uuid}/findings
```

---

## Component 1: Google Workspace Alert Center Source Plugin

### New files

| File | Purpose |
|------|---------|
| `app/integrations/sources/google_workspace.py` | `AlertSourceBase` subclass |
| `docs/integrations/google-workspace/api_notes.md` | API research artifact (required by convention) |
| `scripts/poll_google_alerts.py` | Local polling script |

### Alert Center API shape

The Alert Center API (v1beta1) returns alerts with this top-level structure:

```json
{
  "alertId": "abc123",
  "customerId": "C01234567",
  "createTime": "2026-03-14T10:00:00Z",
  "startTime": "2026-03-14T09:55:00Z",
  "type": "Suspicious login blocked",
  "source": "Google Identity",
  "data": { ... },
  "metadata": {
    "customerId": "C01234567",
    "alertId": "abc123",
    "status": "NOT_STARTED",
    "severity": "HIGH",
    "updateTime": "2026-03-14T10:00:00Z"
  }
}
```

**Key:** `severity` lives in `metadata.severity`, NOT at the top level.

The `data` field is polymorphic — its shape depends on the `type` string. Two primary data types we care about:

**AccountWarning** (suspicious login, leaked password, user suspended):
```json
{
  "data": {
    "@type": "type.googleapis.com/google.apps.alertcenter.type.AccountWarning",
    "email": "user@example.com",
    "loginDetails": {
      "ipAddress": "185.220.101.34",
      "loginTime": "2026-03-14T09:55:00Z"
    }
  }
}
```
Fields: `email` (required), `loginDetails` (optional — only present for login-related warnings). No `maliciousEntity` field on this type.

**MailPhishing** (user-reported phishing, suspicious message, spam spike):
```json
{
  "data": {
    "@type": "type.googleapis.com/google.apps.alertcenter.type.MailPhishing",
    "domainId": { ... },
    "maliciousEntity": {
      "entity": { "emailAddress": "attacker@evil.com", "displayName": "..." },
      "fromHeader": "attacker@evil.com",
      "displayName": "Suspicious Sender"
    },
    "messages": [ ... ],
    "isInternal": false
  }
}
```
Fields: `maliciousEntity.fromHeader` (sender email), `maliciousEntity.entity.emailAddress` (actor), `messages[]` (message details).

**Alert types we handle (v1) — exact API `type` strings:**

AccountWarning types:
- `Suspicious login blocked` — IP, account
- `Suspicious login from a less secure app` — IP, account
- `Suspicious programmatic login` — IP, account
- `Leaked password` — account
- `User suspended` — account
- `User suspended due to suspicious activity` — account

MailPhishing types:
- `User reported phishing` — email (from), account
- `Suspicious message reported` — email (from), account
- `Phishing message detected post-delivery` — email (from), account

UserChanges types (no `data.loginDetails`):
- `Suspended user made active` — account
- `User granted Admin privilege` — account
- `New user Added` — account

StateSponsoredAttack type:
- `Government attack warning` — account

Unmapped alert types pass through with `title = type`, `severity = PENDING`, and best-effort indicator extraction from the `data` dict.

### GoogleWorkspaceSource class

```python
class GoogleWorkspaceSource(AlertSourceBase):
    source_name = "google_workspace"
    display_name = "Google Workspace Alert Center"
```

#### validate_payload(raw)

Returns `True` if `raw` has `alertId` and `type` keys. Does not raise.

#### normalize(raw) → CalsetaAlert

| Alert Center field | CalsetaAlert field |
|---|---|
| `type` | `title` |
| `metadata.severity` (`HIGH`/`MEDIUM`/`LOW`) | `severity` (mapped to `AlertSeverity` enum) |
| `startTime` (fallback `createTime`) | `occurred_at` |
| `"google_workspace"` | `source_name` |
| `source` + `type` narrative | `description` |
| `data.email` (AccountWarning) | `actor_email` |
| `data.loginDetails.ipAddress` (AccountWarning) | `src_ip` |
| `data.maliciousEntity.fromHeader` (MailPhishing) | `email_from` |
| `type` + `source` | `tags` |

Severity mapping:
- `HIGH` → `AlertSeverity.HIGH`
- `MEDIUM` → `AlertSeverity.MEDIUM`
- `LOW` → `AlertSeverity.LOW`
- missing/unknown → `AlertSeverity.PENDING` (consistent with Sentinel pattern)

Google Alert Center does not use `CRITICAL` — we map nothing to it. Agents/humans can escalate via status update.

#### extract_indicators(raw) → list[IndicatorExtract]

Pass 1 extraction from the raw Alert Center payload. Fields vary by data type:

**AccountWarning types** (suspicious login, leaked password, etc.):

| Source path | Indicator type | Condition |
|---|---|---|
| `data.email` | `account` | Non-empty |
| `data.loginDetails.ipAddress` | `ip` | Non-empty, `loginDetails` present |

**MailPhishing types** (user-reported phishing, suspicious message, etc.):

| Source path | Indicator type | Condition |
|---|---|---|
| `data.maliciousEntity.fromHeader` | `email` | Non-empty, contains `@` |
| `data.maliciousEntity.entity.emailAddress` | `account` | Non-empty |

**UserChanges types** (admin privilege, suspended user, etc.):

| Source path | Indicator type | Condition |
|---|---|---|
| `data.email` | `account` | Non-empty (field name TBD — verify against UserChanges schema) |

**All types — best-effort fallback:**
- Walk `data` dict looking for keys containing `email`, `ipAddress`, `ip`, `address` → extract as `account` or `ip` respectively.

Deduplication by `(type, value)` before returning. Pass 2 (normalized fields like `src_ip`, `actor_email`) and Pass 3 (custom mappings) handle additional extraction automatically.

#### verify_webhook_signature(headers, raw_body) → bool

Returns `True` always (no signature — our poller is a trusted local process using API key auth). Logs at `debug` level (not `warning` like the base class default) because the lack of signature verification is intentional for a polled source, not a missing implementation.

#### extract_detection_rule_ref(raw) → str | None

Returns `raw.get("alertId")` — allows linking Alert Center alerts to detection rules if the user creates matching rules in Calseta.

#### documented_extractions() → list[SourcePluginExtraction]

Returns extraction documentation for the source integrations CONTEXT page.

### Registration

In `app/integrations/sources/__init__.py`:

```python
from app.integrations.sources.google_workspace import GoogleWorkspaceSource
source_registry.register(GoogleWorkspaceSource())
```

### Polling script: `scripts/poll_google_alerts.py`

Standalone Python script that runs on the host (not in Docker).

**Dependencies:** `google-auth`, `google-api-python-client`, `httpx` (or `requests`)

**Behavior:**
1. Authenticates using a service account JSON key with domain-wide delegation
2. Impersonates an admin user to call the Alert Center API
3. On each poll cycle:
   - Reads last poll timestamp from `scripts/.google_alerts_last_poll` (ISO 8601)
   - Calls `GET /v1beta1/alerts?filter='createTime >= "..."'&orderBy=createTime asc`
   - For each alert: POSTs the raw JSON to `http://localhost:8000/v1/ingest/google_workspace` with `Authorization: Bearer $CALSETA_API_KEY`
   - Updates last poll timestamp to the latest `createTime` seen
4. Sleeps for `--interval` seconds (default 60), loops

**CLI args:**
- `--credentials` — path to service account JSON (default: `scripts/google-sa-key.json`)
- `--admin-email` — admin email for domain-wide delegation
- `--interval` — poll interval in seconds (default 60)
- `--calseta-url` — Calseta API base URL (default: `http://localhost:8000`)
- `--calseta-key` — Calseta API key (or read from `CALSETA_API_KEY` env var)
- `--backfill` — on first run, how many hours back to look (default 24)

**State file:** `scripts/.google_alerts_last_poll` — single line, ISO 8601 timestamp. Git-ignored.

**Error handling:**
- Google API errors: log and retry next cycle (don't crash)
- Calseta POST errors: log the alert ID and HTTP status, continue with next alert
- Auth errors: log and exit (credentials are wrong — no point retrying)

**Google Cloud setup notes (for api_notes.md):**
1. Enable the Alert Center API in GCP Console
2. Create a service account with domain-wide delegation
3. Grant the service account the Alert Center scopes: `https://www.googleapis.com/auth/apps.alerts`
4. In Google Admin → Security → API Controls → Domain-wide delegation, add the service account client ID with the alerts scope
5. The `--admin-email` must be a Google Workspace admin in the domain

---

## Component 2: Enrichment Configuration

No code changes. Configuration only.

### Steps

1. Add to `.env`:
   ```
   VIRUSTOTAL_API_KEY=your_key_here
   ABUSEIPDB_API_KEY=your_key_here
   ```

2. Restart API and worker:
   ```bash
   docker compose restart api worker
   ```

3. Verify providers are active:
   ```bash
   curl -s -H "Authorization: Bearer $KEY" http://localhost:8000/v1/enrichment-providers | python -m json.tool
   ```
   Both should show `is_active: true` and `is_configured: true`.

### What gets enriched

When a Google Workspace alert is ingested with an IP indicator (e.g., from `loginDetails.ipAddress`):
- **VirusTotal:** reputation score, country, ASN, malicious vote counts
- **AbuseIPDB:** abuse confidence score, ISP, usage type, country, report count

Results stored in `indicators.enrichment_results` JSONB and surfaced in the webhook payload to the agent.

---

## Component 3: Webhook Listener + Claude Code Analysis

### New file: `scripts/alert_listener.py`

Lightweight HTTP server based on Python's `http.server` (zero external dependencies).

**Behavior:**
- Listens on port 9998 (configurable via `PORT` env var)
- On POST to `/webhook`:
  - Saves full JSON payload to `scripts/alerts/{timestamp}_{alert_uuid}.json`
  - Prints one-line summary: `[{timestamp}] Alert: {title} | Severity: {severity} | Indicators: {count}`
- On GET to `/health`: returns `{"status": "ok"}`
- Creates `scripts/alerts/` directory on startup if it doesn't exist

### Agent registration

```bash
curl -X POST http://localhost:8000/v1/agents \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "claude-code-analyst",
    "description": "Local webhook listener for Claude Code security analysis testing",
    "endpoint_url": "http://host.docker.internal:9998/webhook",
    "trigger_on_severities": ["High", "Critical"],
    "is_active": true
  }'
```

Note: `host.docker.internal` is required because the worker runs inside Docker but the listener runs on the host.

### Claude Code analysis workflow

After an alert arrives in `scripts/alerts/`:

1. Read the alert JSON file
2. Analyze:
   - What happened (alert title, description, detection rule)
   - Who/what is involved (indicators + enrichment data)
   - How bad is it (enrichment verdicts, abuse scores, VT reputation)
   - What context applies (matched context documents)
3. Post finding back:
   ```bash
   curl -X POST http://localhost:8000/v1/alerts/{uuid}/findings \
     -H "Authorization: Bearer $KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "agent_name": "claude-code-analyst",
       "summary": "...",
       "confidence": "high|medium|low",
       "recommended_action": "...",
       "evidence": { ... }
     }'
   ```

### FindingCreate schema

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_name` | string (1-255) | yes | `"claude-code-analyst"` |
| `summary` | string (1-50000) | yes | Analysis narrative |
| `confidence` | `"low"` / `"medium"` / `"high"` | no | Confidence in assessment |
| `recommended_action` | string | no | What to do next |
| `evidence` | JSON object | no | Supporting data (max ~500KB) |

---

## End-to-End Test Flow

1. **Start services:** `docker compose up -d` (already running)
2. **Configure enrichment:** Add VT + AbuseIPDB keys to `.env`, restart
3. **Start listener:** `python scripts/alert_listener.py`
4. **Register agent:** curl POST to `/v1/agents`
5. **Start poller:** `python scripts/poll_google_alerts.py --admin-email admin@yourdomain.com --calseta-key cai_...`
6. **Wait for alert:** Poller fetches Alert Center alerts → Calseta ingests → enriches → dispatches to listener
7. **Analyze:** Ask Claude Code to read the captured alert and post a finding
8. **Verify in UI:** Check the alert detail page for the posted finding

### Testing without Google alerts

For testing the pipeline without waiting for real alerts, we can use the generic ingest endpoint with a synthetic Google Workspace payload:

```bash
curl -X POST http://localhost:8000/v1/ingest/google_workspace \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "alertId": "test-001",
    "type": "Suspicious login blocked",
    "source": "Google Identity",
    "createTime": "2026-03-14T10:00:00Z",
    "startTime": "2026-03-14T09:55:00Z",
    "metadata": {
      "severity": "HIGH",
      "status": "NOT_STARTED"
    },
    "data": {
      "@type": "type.googleapis.com/google.apps.alertcenter.type.AccountWarning",
      "email": "j.martinez@contoso.com",
      "loginDetails": {
        "ipAddress": "185.220.101.34",
        "loginTime": "2026-03-14T09:55:00Z"
      }
    }
  }'
```

This exercises the full pipeline: source plugin → indicators → enrichment → webhook dispatch.

---

## Files Changed / Created

| File | Action | Description |
|------|--------|-------------|
| `app/integrations/sources/google_workspace.py` | Create | AlertSourceBase subclass |
| `app/integrations/sources/__init__.py` | Edit | Register GoogleWorkspaceSource |
| `docs/integrations/google-workspace/api_notes.md` | Create | API research artifact |
| `scripts/poll_google_alerts.py` | Create | Local polling script |
| `scripts/alert_listener.py` | Create | Webhook listener for Claude Code analysis |
| `.env` | Edit | Add VT + AbuseIPDB API keys |
| `.gitignore` | Edit | Add `scripts/.google_alerts_last_poll`, `scripts/alerts/`, `scripts/google-sa-key.json` |

## Out of Scope

- Production deployment of the poller (Cloud Function, cron job)
- Webhook signature verification for Google Workspace (polled source, not webhook-pushed)
- Additional Google Workspace alert types beyond v1 list
- Autonomous agent loop (agent calls Claude API directly)
- MCP server integration for the agent
- UI changes
