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


def forward_to_calseta(client: httpx.Client, alert: dict, calseta_url: str) -> dict:
    """POST a single alert to Calseta's ingest endpoint."""
    resp = client.post(
        f"{calseta_url}/v1/ingest/google_workspace",
        json=alert,
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
    with httpx.Client(
        timeout=30,
        headers={"Authorization": f"Bearer {args.calseta_key}"},
    ) as client:
        for alert in alerts:
            try:
                result = forward_to_calseta(client, alert, args.calseta_url)
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
