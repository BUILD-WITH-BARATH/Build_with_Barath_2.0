from fastapi.testclient import TestClient
from app import app, db, engine, DEMO_PASSWORD, DEMO_TENANT_ID, TENANT_SIGNUP_KEY
import time

client = TestClient(app)


def auth_headers(subject: str, password: str = DEMO_PASSWORD) -> dict:
    """Log in as `subject` (registering it first if it isn't a seeded demo
    account) and return the Authorization header for it."""
    res = client.post("/auth/login", json={"subject": subject, "password": password})
    if res.status_code != 200:
        client.post("/auth/register", json={"subject": subject, "password": password})
        res = client.post("/auth/login", json={"subject": subject, "password": password})
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def setup_module(module):
    client.post("/reset")

def setup_function(function):
    client.post("/reset")

def test_1_normal_owner():
    res = client.get("/records/1", headers=auth_headers("alice"))
    assert res.status_code == 200

def test_2_normal_assigned():
    res = client.get("/records/1", headers=auth_headers("dr_singh"))
    assert res.status_code == 200

def test_3_normal_delegated():
    res = client.get("/records/17", headers=auth_headers("support_amy"))
    assert res.status_code == 200

def test_4_normal_denied():
    res = client.get("/records/99", headers=auth_headers("alice"))
    assert res.status_code == 403

def test_5_rapid_bola():
    headers = auth_headers("bob")
    for i in range(200, 205):
        client.get(f"/records/{i}", headers=headers)
    res = client.get("/risk/bob")
    assert res.json()["score"] >= 45

def test_6_sequential_enumeration():
    headers = auth_headers("attacker_2")
    for i in [300, 301, 302, 303]:
        client.get(f"/records/{i}", headers=headers)
    res = client.get("/risk/attacker_2")
    assert "sequential_id_enumeration" in res.json()["signals"]

def test_7_low_and_slow():
    subject = "attacker_slow"
    now = time.time()
    for i in range(16):
        engine.record_event(DEMO_TENANT_ID, subject, 50 + i, False, now - 3600 + i * 200, "records")
    res = client.get("/records/66", headers=auth_headers(subject))
    res_risk = client.get(f"/risk/{subject}")
    assert "low_and_slow_reconnaissance" in res_risk.json()["signals"]

def test_8_high_failure_ratio():
    headers = auth_headers("attacker_4")
    for _ in range(7):
        client.get("/records/400", headers=headers)
    res = client.get("/risk/attacker_4")
    assert "high_failure_ratio" in res.json()["signals"]

def test_9_simulate_normal():
    res = client.post("/simulate/normal")
    assert res.status_code == 200

def test_10_simulate_rapid():
    res = client.post("/simulate/rapid")
    assert res.status_code == 200

def test_11_simulate_low_and_slow():
    res = client.post("/simulate/low_and_slow")
    assert res.status_code == 200

def test_12_no_unauthorized_leak():
    res = client.get("/records/99", headers=auth_headers("alice"))
    assert res.status_code == 403
    assert "record" not in res.json()

def test_13_non_sequential():
    headers = auth_headers("attacker_5")
    for i in [500, 600, 700, 800]:
        client.get(f"/records/{i}", headers=headers)
    res = client.get("/risk/attacker_5")
    assert "sequential_id_enumeration" not in res.json()["signals"]
    assert "unauthorized_unique_object_pressure" in res.json()["signals"]

def test_14_legitimate_burst():
    headers = auth_headers("alice")
    for i in range(1, 10):
        client.get(f"/records/{i}", headers=headers)
    res = client.get("/risk/alice")
    assert res.json()["score"] == 0

def test_15_same_id_repeated():
    headers = auth_headers("attacker_6")
    for _ in range(5):
        client.get("/records/100", headers=headers)
    res = client.get("/risk/attacker_6")
    assert "unauthorized_unique_object_pressure" not in res.json()["signals"]

def test_16_risk_calculation():
    client.get("/records/100", headers=auth_headers("attacker_7"))
    res = client.get("/risk/attacker_7")
    assert res.json()["score"] > 0
    assert "unique_denied_short" in res.json()["contributions"]

def test_17_max_100_cap():
    subject = "attacker_8"
    now = time.time()
    for i in range(20):
        engine.record_event(DEMO_TENANT_ID, subject, 900 + i, False, now, "records")
    res = client.get("/risk/attacker_8")
    assert res.json()["score"] == 100

def test_18_blocking():
    headers = auth_headers("attacker_9")
    res = None
    for i in range(1000, 1020):
        res = client.get(f"/records/{i}", headers=headers)
    assert res.status_code == 403
    assert res.json()["detail"]["outcome"] == "blocked"

def test_19_post_blocking():
    engine._set_blocked_until(DEMO_TENANT_ID, "attacker_10", time.time() + 300)
    res = client.get("/records/10", headers=auth_headers("attacker_10"))
    assert res.status_code == 403
    assert res.json()["detail"]["outcome"] == "blocked"

def test_20_history_cleanup():
    subject = "attacker_11"
    now = time.time()
    engine.record_event(DEMO_TENANT_ID, subject, 50, False, now - 4000, "records")
    engine.cleanup_stale(DEMO_TENANT_ID)
    assert engine._events(DEMO_TENANT_ID, subject, now) == []

def test_21_endpoint_diversity():
    headers = auth_headers("attacker_12")
    client.get("/users/1", headers=headers)
    client.get("/invoices/1", headers=headers)
    res = client.get("/risk/attacker_12")
    assert "endpoint_diversity" in res.json()["signals"]

def test_22_global_aggregation():
    for i in range(55):
        auth_headers(f"dummy_{i}")
    for i in range(55):
        client.get("/records/999", headers=auth_headers(f"dummy_{i}"))
    res = client.get("/stats")
    assert "999" in res.json()["coordinated_attacks"] or 999 in res.json()["coordinated_attacks"]

def test_23_config():
    res = client.get("/config")
    assert "short_window" in res.json()

def test_24_invariants():
    res = client.get("/risk/alice")
    assert "score" in res.json()
    assert "contributions" in res.json()
    total = sum(res.json()["contributions"].values())
    if total <= 100:
        assert total == res.json()["score"]

def test_25_login_requires_correct_password():
    res = client.post("/auth/login", json={"subject": "alice", "password": "wrong-password"})
    assert res.status_code == 401

def test_26_records_requires_auth():
    res = client.get("/records/1")
    assert res.status_code == 401

def test_27_admin_endpoints_require_admin_role():
    res = client.post("/admin/approve-ban/alice", headers=auth_headers("bob"))
    assert res.status_code == 403

def test_28_admin_endpoints_work_for_security_admin():
    import os
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin_changeme123")
    headers = auth_headers("security_admin", admin_password)
    res = client.get("/admin/pending-bans", headers=headers)
    assert res.status_code == 200


# --- Multi-tenant product API (/v1/*) ---

def create_test_tenant(name: str) -> tuple[str, str]:
    res = client.post("/v1/tenants", json={"name": name}, headers={"X-Signup-Key": TENANT_SIGNUP_KEY})
    assert res.status_code == 200, res.text
    body = res.json()
    return body["tenant_id"], body["api_key"]

def test_29_tenant_signup_requires_correct_key():
    res = client.post("/v1/tenants", json={"name": "acme"}, headers={"X-Signup-Key": "wrong-key"})
    assert res.status_code == 403

def test_30_tenant_signup_creates_usable_api_key():
    tenant_id, api_key = create_test_tenant("acme-corp")
    assert tenant_id and api_key.startswith("sk_")

def test_31_v1_authorize_requires_api_key():
    res = client.post("/v1/authorize", json={"subject": "u1", "resource_id": "r1", "authorized": True})
    assert res.status_code == 401

def test_32_v1_authorize_rejects_bad_api_key():
    res = client.post("/v1/authorize", json={"subject": "u1", "resource_id": "r1", "authorized": True},
                       headers={"X-API-Key": "sk_not_a_real_key"})
    assert res.status_code == 401

def test_33_v1_authorize_allows_when_caller_says_authorized():
    _tenant_id, api_key = create_test_tenant("acme-33")
    res = client.post("/v1/authorize", json={"subject": "u1", "resource_id": "r1", "authorized": True},
                       headers={"X-API-Key": api_key})
    assert res.status_code == 200
    body = res.json()
    assert body["decision"] == "allow"
    assert body["score"] == 0

def test_34_v1_authorize_denies_when_caller_says_unauthorized():
    _tenant_id, api_key = create_test_tenant("acme-34")
    res = client.post("/v1/authorize", json={"subject": "u1", "resource_id": "r1", "authorized": False},
                       headers={"X-API-Key": api_key})
    assert res.status_code == 200
    assert res.json()["decision"] == "deny"

def test_35_v1_authorize_escalates_to_block_on_bola_pattern():
    _tenant_id, api_key = create_test_tenant("acme-35")
    headers = {"X-API-Key": api_key}
    last = None
    for i in range(20):
        last = client.post("/v1/authorize", json={"subject": "attacker", "resource_id": f"r{i}", "authorized": False},
                            headers=headers)
    assert last.json()["decision"] == "block"

def test_36_tenant_isolation_risk_engine():
    """Tenant A's attack pattern must never affect tenant B's risk score for the same subject name."""
    _tenant_a, key_a = create_test_tenant("isolated-a")
    _tenant_b, key_b = create_test_tenant("isolated-b")
    for i in range(20):
        client.post("/v1/authorize", json={"subject": "shared_name", "resource_id": f"r{i}", "authorized": False},
                    headers={"X-API-Key": key_a})
    res_b = client.post("/v1/authorize", json={"subject": "shared_name", "resource_id": "r0", "authorized": True},
                         headers={"X-API-Key": key_b})
    assert res_b.json()["decision"] == "allow"
    assert res_b.json()["score"] == 0

def test_37_tenant_isolation_demo_unaffected():
    """A product-API tenant's traffic must never leak into the demo dashboard's /stats."""
    _tenant_id, api_key = create_test_tenant("isolated-demo-check")
    before = client.get("/stats").json()
    for i in range(10):
        client.post("/v1/authorize", json={"subject": "other_tenant_subject", "resource_id": f"r{i}", "authorized": False},
                    headers={"X-API-Key": api_key})
    after = client.get("/stats").json()
    assert after["active_subjects"] == before["active_subjects"]


def test_38_healthz():
    res = client.get("/healthz")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_39_strike_retention_beyond_sliding_window():
    """Strikes must NOT be purged by the 5-minute sliding window (long_window).
    They must be retained across lockout durations so repeat offenders escalate to Strike 2 and 3."""
    subject = "persistent_adversary"
    tenant_id = DEMO_TENANT_ID
    now = time.time()

    # Issue Strike 1 at t0
    engine.register_strike_and_block(tenant_id, subject, now)
    assert engine.get_strike_count(tenant_id, subject, now) == 1

    # Simulate 10 minutes passing (600s > 300s long_window)
    future_now = now + 600
    engine.cleanup_stale(tenant_id)

    # Strike 1 must still exist at future_now
    assert engine.get_strike_count(tenant_id, subject, future_now) == 1

    # Issue Strike 2
    engine.register_strike_and_block(tenant_id, subject, future_now)
    assert engine.get_strike_count(tenant_id, subject, future_now) == 2

