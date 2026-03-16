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

        # AccountWarning / UserChanges fields
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

        # Best-effort fallback: walk data dict for keys containing email/ip patterns.
        # Catches indicators from unmapped/future alert types.
        for key, val in data.items():
            if not isinstance(val, str) or not val:
                continue
            key_lower = key.lower()
            if "email" in key_lower and "@" in val:
                _add(IndicatorType.ACCOUNT, val, f"data.{key}")
            elif (key_lower.startswith("ip") or key_lower.endswith("ip") or "ipaddress" in key_lower or "ip_address" in key_lower or key_lower == "address") and "." in val:
                _add(IndicatorType.IP, val, f"data.{key}")

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
            _e("data.email", "account", "AccountWarning/UserChanges: user email"),
            _e("data.loginDetails.ipAddress", "ip", "AccountWarning: login IP"),
            _e("data.maliciousEntity.fromHeader", "email", "MailPhishing: sender email"),
            _e("data.maliciousEntity.entity.emailAddress", "account", "MailPhishing: attacker email"),
        ]
