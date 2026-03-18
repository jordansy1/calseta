"""Tests for Google Workspace Alert Center source integration."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.integrations.sources.google_workspace import GoogleWorkspaceSource
from app.schemas.alert import AlertSeverity
from app.schemas.indicators import IndicatorType

GWS = GoogleWorkspaceSource
FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:  # type: ignore[type-arg]
    return dict(json.loads((FIXTURES / name).read_text()))


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

    @pytest.fixture
    def user_changes(self) -> dict:
        return _load("google_workspace_user_changes.json")

    # --- source_name ---

    def test_source_name(self, source: GWS) -> None:
        assert source.source_name == "google_workspace"

    def test_display_name(self, source: GWS) -> None:
        assert source.display_name == "Google Workspace Alert Center"

    # --- validate_payload ---

    def test_validate_valid_account_warning(self, source: GWS, account_warning: dict) -> None:
        assert source.validate_payload(account_warning) is True

    def test_validate_valid_mail_phishing(self, source: GWS, mail_phishing: dict) -> None:
        assert source.validate_payload(mail_phishing) is True

    def test_validate_empty_dict(self, source: GWS) -> None:
        assert source.validate_payload({}) is False

    def test_validate_missing_type(self, source: GWS) -> None:
        assert source.validate_payload({"alertId": "abc"}) is False

    def test_validate_missing_alert_id(self, source: GWS) -> None:
        assert source.validate_payload({"type": "Suspicious login blocked"}) is False

    # --- normalize: AccountWarning ---

    def test_normalize_title(self, source: GWS, account_warning: dict) -> None:
        alert = source.normalize(account_warning)
        assert alert.title == "Suspicious login blocked"

    def test_normalize_severity_from_metadata(self, source: GWS, account_warning: dict) -> None:
        alert = source.normalize(account_warning)
        assert alert.severity == AlertSeverity.HIGH

    def test_normalize_severity_missing_metadata(self, source: GWS, account_warning: dict) -> None:
        del account_warning["metadata"]
        alert = source.normalize(account_warning)
        assert alert.severity == AlertSeverity.PENDING

    def test_normalize_occurred_at_start_time(self, source: GWS, account_warning: dict) -> None:
        alert = source.normalize(account_warning)
        assert alert.occurred_at == datetime(2026, 3, 14, 9, 55, tzinfo=UTC)

    def test_normalize_occurred_at_fallback(self, source: GWS, account_warning: dict) -> None:
        del account_warning["startTime"]
        alert = source.normalize(account_warning)
        assert alert.occurred_at == datetime(2026, 3, 14, 10, 0, tzinfo=UTC)

    def test_normalize_source_name(self, source: GWS, account_warning: dict) -> None:
        alert = source.normalize(account_warning)
        assert alert.source_name == "google_workspace"

    def test_normalize_actor_email(self, source: GWS, account_warning: dict) -> None:
        alert = source.normalize(account_warning)
        assert alert.actor_email == "j.martinez@contoso.com"

    def test_normalize_src_ip(self, source: GWS, account_warning: dict) -> None:
        alert = source.normalize(account_warning)
        assert alert.src_ip == "185.220.101.34"

    # --- normalize: MailPhishing ---

    def test_normalize_phishing_title(self, source: GWS, mail_phishing: dict) -> None:
        alert = source.normalize(mail_phishing)
        assert alert.title == "User reported phishing"

    def test_normalize_phishing_severity(self, source: GWS, mail_phishing: dict) -> None:
        alert = source.normalize(mail_phishing)
        assert alert.severity == AlertSeverity.MEDIUM

    def test_normalize_phishing_email_from(self, source: GWS, mail_phishing: dict) -> None:
        alert = source.normalize(mail_phishing)
        assert alert.email_from == "support@evil-domain.com"

    # --- normalize + extract_indicators: UserChanges ---

    def test_normalize_user_changes_title(self, source: GWS, user_changes: dict) -> None:
        alert = source.normalize(user_changes)
        assert alert.title == "User granted Admin privilege"

    def test_normalize_user_changes_actor_email(self, source: GWS, user_changes: dict) -> None:
        alert = source.normalize(user_changes)
        assert alert.actor_email == "new-admin@contoso.com"

    def test_extract_indicators_user_changes(self, source: GWS, user_changes: dict) -> None:
        indicators = source.extract_indicators(user_changes)
        types = {(i.type, i.value) for i in indicators}
        assert (IndicatorType.ACCOUNT, "new-admin@contoso.com") in types

    # --- extract_indicators: AccountWarning ---

    def test_extract_indicators_account_warning(self, source: GWS, account_warning: dict) -> None:
        indicators = source.extract_indicators(account_warning)
        types = {(i.type, i.value) for i in indicators}
        assert (IndicatorType.IP, "185.220.101.34") in types
        assert (IndicatorType.ACCOUNT, "j.martinez@contoso.com") in types

    def test_extract_indicators_no_login_details(self, source: GWS, account_warning: dict) -> None:
        del account_warning["data"]["loginDetails"]
        indicators = source.extract_indicators(account_warning)
        types = {(i.type, i.value) for i in indicators}
        assert (IndicatorType.ACCOUNT, "j.martinez@contoso.com") in types
        assert not any(i.type == IndicatorType.IP for i in indicators)

    # --- extract_indicators: MailPhishing ---

    def test_extract_indicators_mail_phishing(self, source: GWS, mail_phishing: dict) -> None:
        indicators = source.extract_indicators(mail_phishing)
        types = {(i.type, i.value) for i in indicators}
        assert (IndicatorType.EMAIL, "support@evil-domain.com") in types
        assert (IndicatorType.ACCOUNT, "attacker@evil-domain.com") in types

    # --- extract_indicators: unmapped/unknown type with fallback ---

    def test_normalize_unknown_type_uses_pending_severity(self, source: GWS) -> None:
        raw = {
            "alertId": "unknown-001",
            "type": "Some Future Alert Type",
            "source": "Unknown Source",
            "createTime": "2026-03-14T10:00:00Z",
            "data": {"someField": "someValue", "contactEmail": "user@example.com"},
            "metadata": {},
        }
        alert = source.normalize(raw)
        assert alert.severity == AlertSeverity.PENDING
        assert alert.title == "Some Future Alert Type"

    def test_extract_indicators_fallback_finds_email_keys(self, source: GWS) -> None:
        """Best-effort fallback: walks data dict for keys containing 'email' or 'ip'."""
        raw = {
            "alertId": "unknown-002",
            "type": "Some Future Alert Type",
            "data": {"contactEmail": "user@example.com", "sourceIpAddress": "10.0.0.1"},
        }
        indicators = source.extract_indicators(raw)
        types = {(i.type, i.value) for i in indicators}
        assert (IndicatorType.ACCOUNT, "user@example.com") in types
        assert (IndicatorType.IP, "10.0.0.1") in types

    # --- extract_indicators: empty/invalid ---

    def test_extract_indicators_empty_data(self, source: GWS) -> None:
        result = source.extract_indicators({"alertId": "x", "type": "Unknown", "data": {}})
        assert isinstance(result, list)

    # --- extract_detection_rule_ref ---

    def test_extract_detection_rule_ref(self, source: GWS, account_warning: dict) -> None:
        ref = source.extract_detection_rule_ref(account_warning)
        assert ref == "gw-test-001"

    # --- verify_webhook_signature ---

    def test_verify_webhook_signature_always_true(self, source: GWS) -> None:
        assert source.verify_webhook_signature({}, b"") is True

    # --- documented_extractions ---

    def test_documented_extractions_not_empty(self, source: GWS) -> None:
        extractions = source.documented_extractions()
        assert len(extractions) > 0
