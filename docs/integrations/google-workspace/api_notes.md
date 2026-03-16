# Google Workspace Alert Center — API Notes

> Research artifact required by Calseta convention before shipping integration code.

## API Overview

- **Service:** Google Workspace Alert Center API
- **Version:** v1beta1 (stable enough for production use per Google docs)
- **Base URL:** `https://alertcenter.googleapis.com/v1beta1`
- **Auth:** Service account with domain-wide delegation
- **Required scope:** `https://www.googleapis.com/auth/apps.alerts`
- **Rate limit:** 5 QPS default quota

## Alert Resource Fields

| Field | Type | Notes |
|-------|------|-------|
| `alertId` | string | Unique alert identifier |
| `customerId` | string | Google Workspace customer ID |
| `createTime` | timestamp | When Google created the alert |
| `startTime` | timestamp | When the event actually occurred (use this for `occurred_at`) |
| `endTime` | timestamp | When the event ended (optional) |
| `type` | string | Alert type string (e.g., "Suspicious login blocked") |
| `source` | string | Alert source (e.g., "Google Identity", "Gmail phishing") |
| `data` | object | Polymorphic — type determined by `data.@type` |
| `metadata` | object | Contains `severity`, `status`, `updateTime` |

### Critical: Severity Location

Severity is in `metadata.severity`, **NOT** top-level. Values: `HIGH`, `MEDIUM`, `LOW`.
Google does not use `CRITICAL` or `INFORMATIONAL`.

## Key Data Types

### AccountWarning (`type.googleapis.com/google.apps.alertcenter.type.AccountWarning`)
- Alert types: "Suspicious login blocked", "Suspicious login", "Leaked password"
- `data.email` — affected user email
- `data.loginDetails.ipAddress` — source IP of login attempt
- `data.loginDetails.loginTime` — when login occurred

### MailPhishing (`type.googleapis.com/google.apps.alertcenter.type.MailPhishing`)
- Alert types: "User reported phishing"
- `data.maliciousEntity.fromHeader` — sender display email
- `data.maliciousEntity.entity.emailAddress` — actual attacker email
- `data.messages[]` — list of affected messages with `messageId`, hashes
- `data.isInternal` — whether the phishing was internal

### UserChanges (`type.googleapis.com/google.apps.alertcenter.type.UserChanges`)
- Alert types: "Suspended user made active", "User granted Admin privilege", "New user Added"
- `data.email` — affected user email

### Other types (not mapped, handled by best-effort fallback)
- `StateSponsoredAttack` — government-backed attack warnings
- `DeviceCompromised` — managed device alerts
- `SuspiciousActivity` — various suspicious activity alerts

## Pagination

- `pageSize` max: 100 (API default: unspecified, we request 100)
- `pageToken` / `nextPageToken` in response
- Use `service.alerts().list_next(request, response)` for automatic pagination

## Filter Syntax

- `createTime >= "2026-03-13T00:00:00Z"` — ISO 8601 timestamp filter
- Only `createTime` is filterable (not `startTime`)
- Combine with `orderBy="createTime asc"` for chronological processing

## Edge Cases

1. **Polymorphic `data` field:** The `@type` field determines the schema. Unmapped types
   pass through with `severity = PENDING` and best-effort indicator extraction.
2. **Missing `startTime`:** Some alerts only have `createTime`. Our source falls back to
   `createTime` when `startTime` is absent.
3. **`fromHeader` vs `entity.emailAddress`:** In MailPhishing, `fromHeader` is the displayed
   sender (may be spoofed), while `entity.emailAddress` is the actual sender account.
4. **No webhook support:** Alert Center is pull-only. We use a manual fetch script with
   time-range parameters.
