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
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
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
