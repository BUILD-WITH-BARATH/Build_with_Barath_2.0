"""
Phase 6: third-party SIEM/observability integrations - Datadog and Splunk.

Both are off by default (graceful degradation, same pattern as SMTP_ENABLED
in alerting.py) and use synchronous HTTP with a short timeout so they can be
called directly from the existing sync SOC-alert path without needing an
event loop. A forwarding failure never raises - it's swallowed and logged,
since a SIEM being down should never block or fail the request that
triggered the alert.

Datadog also gets real value for free from Phase 1's existing /metrics
endpoint: point a Datadog Agent's OpenMetrics check at it (see README) rather
than reimplementing metrics forwarding here.
"""
from __future__ import annotations

import os
import time
from typing import Optional

import httpx

# ---- Datadog Events API (https://docs.datadoghq.com/api/latest/events/) ----
DATADOG_ENABLED = os.environ.get("DATADOG_ENABLED", "false").lower() == "true"
DATADOG_API_KEY = os.environ.get("DATADOG_API_KEY", "")
DATADOG_SITE = os.environ.get("DATADOG_SITE", "datadoghq.com")  # e.g. datadoghq.eu for the EU region
DATADOG_TIMEOUT_SECONDS = float(os.environ.get("DATADOG_TIMEOUT_SECONDS", "3.0"))

# ---- Splunk HTTP Event Collector (https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector) ----
SPLUNK_HEC_ENABLED = os.environ.get("SPLUNK_HEC_ENABLED", "false").lower() == "true"
SPLUNK_HEC_URL = os.environ.get("SPLUNK_HEC_URL", "")  # e.g. https://splunk.example.com:8088
SPLUNK_HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "")
SPLUNK_HEC_TIMEOUT_SECONDS = float(os.environ.get("SPLUNK_HEC_TIMEOUT_SECONDS", "3.0"))
SPLUNK_HEC_SOURCETYPE = os.environ.get("SPLUNK_HEC_SOURCETYPE", "cyberaccess:soc_alert")


def forward_to_datadog(alert_payload: dict) -> bool:
    """Forward a SOC alert as a Datadog Event. Returns False (never raises) on
    any failure or if not configured."""
    if not DATADOG_ENABLED or not DATADOG_API_KEY:
        return False
    try:
        severity = str(alert_payload.get("severity", "HIGH"))
        with httpx.Client(timeout=DATADOG_TIMEOUT_SECONDS) as client:
            resp = client.post(
                f"https://api.{DATADOG_SITE}/api/v1/events",
                headers={"DD-API-KEY": DATADOG_API_KEY, "Content-Type": "application/json"},
                json={
                    "title": f"CyberAccess SOC Alert: {alert_payload.get('threat_type', 'BOLA_ENUMERATION_ATTACK')}",
                    "text": (
                        f"Tenant: {alert_payload.get('tenant_id')}\n"
                        f"Subject: {alert_payload.get('attacker_identity')}\n"
                        f"Risk score: {alert_payload.get('risk_score')} ({alert_payload.get('risk_category')})\n"
                        f"Signals: {', '.join(alert_payload.get('signals_tripped', []))}\n"
                        f"Mitigation: {alert_payload.get('mitigation_action')}"
                    ),
                    "alert_type": "error" if severity == "CRITICAL" else "warning",
                    "source_type_name": "cyberaccess",
                    "tags": [
                        f"tenant:{alert_payload.get('tenant_id')}",
                        f"severity:{severity.lower()}",
                        f"escalation:{alert_payload.get('escalation_tier', 'unknown')}",
                    ],
                    "date_happened": int(alert_payload.get("timestamp", time.time())),
                },
            )
            return resp.status_code in (200, 202)
    except Exception:
        return False


def forward_to_splunk(alert_payload: dict) -> bool:
    """Forward a SOC alert to Splunk via the HTTP Event Collector. Returns
    False (never raises) on any failure or if not configured."""
    if not SPLUNK_HEC_ENABLED or not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        return False
    try:
        with httpx.Client(timeout=SPLUNK_HEC_TIMEOUT_SECONDS) as client:
            resp = client.post(
                f"{SPLUNK_HEC_URL.rstrip('/')}/services/collector/event",
                headers={"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"},
                json={
                    "time": alert_payload.get("timestamp", time.time()),
                    "sourcetype": SPLUNK_HEC_SOURCETYPE,
                    "event": alert_payload,
                },
            )
            return resp.status_code == 200
    except Exception:
        return False


def forward_soc_alert(alert_payload: dict) -> dict:
    """Fan out a SOC alert to every configured SIEM integration. Each
    forwarder degrades independently - a Datadog outage never blocks the
    Splunk forward or vice versa."""
    return {
        "datadog": forward_to_datadog(alert_payload),
        "splunk": forward_to_splunk(alert_payload),
    }
