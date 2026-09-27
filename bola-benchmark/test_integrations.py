"""
Tests for Phase 6 third-party SIEM integrations (Datadog, Splunk).
Uses httpx.MockTransport so no real network call is ever made.
"""
import httpx
import pytest

import integrations


SAMPLE_ALERT = {
    "alert_id": "SOC-ALERT-123",
    "tenant_id": "demo",
    "timestamp": 1234567890,
    "severity": "CRITICAL",
    "threat_type": "BOLA_ENUMERATION_ATTACK",
    "attacker_identity": "attacker_1",
    "risk_score": 100,
    "risk_category": "Attack",
    "signals_tripped": ["canary_honeypot_triggered"],
    "escalation_tier": "PERMANENT_BLACKLIST",
    "mitigation_action": "PERMANENT_IDENTITY_BLACKLIST",
}


def _mock_client_factory(handler):
    class MockClient(httpx.Client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)
    return MockClient


def test_datadog_disabled_by_default(monkeypatch):
    monkeypatch.setattr(integrations, "DATADOG_ENABLED", False)
    assert integrations.forward_to_datadog(SAMPLE_ALERT) is False


def test_datadog_forwards_when_enabled(monkeypatch):
    captured = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(202, json={"status": "ok"})

    monkeypatch.setattr(integrations, "DATADOG_ENABLED", True)
    monkeypatch.setattr(integrations, "DATADOG_API_KEY", "dd_test_key")
    monkeypatch.setattr(integrations.httpx, "Client", _mock_client_factory(handler))

    result = integrations.forward_to_datadog(SAMPLE_ALERT)

    assert result is True
    assert len(captured) == 1
    assert captured[0].url.host == "api.datadoghq.com"
    assert captured[0].headers["dd-api-key"] == "dd_test_key"


def test_datadog_returns_false_on_error_status(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"errors": ["Forbidden"]})

    monkeypatch.setattr(integrations, "DATADOG_ENABLED", True)
    monkeypatch.setattr(integrations, "DATADOG_API_KEY", "dd_bad_key")
    monkeypatch.setattr(integrations.httpx, "Client", _mock_client_factory(handler))

    assert integrations.forward_to_datadog(SAMPLE_ALERT) is False


def test_datadog_never_raises_on_network_failure(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(integrations, "DATADOG_ENABLED", True)
    monkeypatch.setattr(integrations, "DATADOG_API_KEY", "dd_test_key")
    monkeypatch.setattr(integrations.httpx, "Client", _mock_client_factory(handler))

    assert integrations.forward_to_datadog(SAMPLE_ALERT) is False


def test_splunk_disabled_by_default(monkeypatch):
    monkeypatch.setattr(integrations, "SPLUNK_HEC_ENABLED", False)
    assert integrations.forward_to_splunk(SAMPLE_ALERT) is False


def test_splunk_forwards_when_enabled(monkeypatch):
    captured = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"text": "Success", "code": 0})

    monkeypatch.setattr(integrations, "SPLUNK_HEC_ENABLED", True)
    monkeypatch.setattr(integrations, "SPLUNK_HEC_URL", "https://splunk.example.com:8088")
    monkeypatch.setattr(integrations, "SPLUNK_HEC_TOKEN", "splunk_test_token")
    monkeypatch.setattr(integrations.httpx, "Client", _mock_client_factory(handler))

    result = integrations.forward_to_splunk(SAMPLE_ALERT)

    assert result is True
    assert len(captured) == 1
    assert captured[0].url.host == "splunk.example.com"
    assert captured[0].headers["authorization"] == "Splunk splunk_test_token"


def test_splunk_missing_config_short_circuits(monkeypatch):
    monkeypatch.setattr(integrations, "SPLUNK_HEC_ENABLED", True)
    monkeypatch.setattr(integrations, "SPLUNK_HEC_URL", "")
    monkeypatch.setattr(integrations, "SPLUNK_HEC_TOKEN", "")
    assert integrations.forward_to_splunk(SAMPLE_ALERT) is False


def test_forward_soc_alert_fans_out_independently(monkeypatch):
    def datadog_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"status": "ok"})

    monkeypatch.setattr(integrations, "DATADOG_ENABLED", True)
    monkeypatch.setattr(integrations, "DATADOG_API_KEY", "dd_test_key")
    monkeypatch.setattr(integrations, "SPLUNK_HEC_ENABLED", True)
    monkeypatch.setattr(integrations, "SPLUNK_HEC_URL", "https://splunk.example.com:8088")
    monkeypatch.setattr(integrations, "SPLUNK_HEC_TOKEN", "")  # deliberately misconfigured

    monkeypatch.setattr(integrations.httpx, "Client", _mock_client_factory(datadog_handler))

    result = integrations.forward_soc_alert(SAMPLE_ALERT)

    # Datadog succeeds even though Splunk is misconfigured - one integration's
    # failure must never affect another's.
    assert result == {"datadog": True, "splunk": False}
