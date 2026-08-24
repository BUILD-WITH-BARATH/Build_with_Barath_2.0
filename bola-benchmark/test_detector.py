from fastapi.testclient import TestClient
from app import app, db, seed_database, engine, Event
import time

client = TestClient(app)

def setup_module(module):
    client.post("/reset")

def setup_function(function):
    client.post("/reset")

def test_1_normal_owner():
    res = client.get("/records/1", headers={"X-Subject": "alice"})
    assert res.status_code == 200

def test_2_normal_assigned():
    res = client.get("/records/1", headers={"X-Subject": "dr_singh"})
    assert res.status_code == 200

def test_3_normal_delegated():
    res = client.get("/records/17", headers={"X-Subject": "support_amy"})
    assert res.status_code == 200

def test_4_normal_denied():
    res = client.get("/records/99", headers={"X-Subject": "alice"})
    assert res.status_code == 403

def test_5_rapid_bola():
    for i in range(200, 205):
        client.get(f"/records/{i}", headers={"X-Subject": "bob"})
    res = client.get("/risk/bob")
    assert res.json()["score"] >= 45

def test_6_sequential_enumeration():
    for i in [300, 301, 302, 303]:
        client.get(f"/records/{i}", headers={"X-Subject": "attacker_2"})
    res = client.get("/risk/attacker_2")
    assert "sequential_id_enumeration" in res.json()["signals"]

def test_7_low_and_slow():
    subject = "attacker_slow"
    now = time.time()
    for i in range(16):
        engine.history[subject].append(Event(50+i, False, now - 3600 + i*200, "records"))
    res = client.get(f"/records/66", headers={"X-Subject": subject})
    res_risk = client.get(f"/risk/{subject}")
    assert "low_and_slow_reconnaissance" in res_risk.json()["signals"]

def test_8_high_failure_ratio():
    for _ in range(7):
        client.get("/records/400", headers={"X-Subject": "attacker_4"})
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
    res = client.get("/records/99", headers={"X-Subject": "alice"})
    assert res.status_code == 403
    assert "record" not in res.json()

def test_13_non_sequential():
    for i in [500, 600, 700, 800]:
        client.get(f"/records/{i}", headers={"X-Subject": "attacker_5"})
    res = client.get("/risk/attacker_5")
    assert "sequential_id_enumeration" not in res.json()["signals"]
    assert "unauthorized_unique_object_pressure" in res.json()["signals"]

def test_14_legitimate_burst():
    for i in range(1, 10):
        client.get(f"/records/{i}", headers={"X-Subject": "alice"})
    res = client.get("/risk/alice")
    assert res.json()["score"] == 0

def test_15_same_id_repeated():
    for _ in range(5):
        client.get("/records/100", headers={"X-Subject": "attacker_6"})
    res = client.get("/risk/attacker_6")
    assert "unauthorized_unique_object_pressure" not in res.json()["signals"]

def test_16_risk_calculation():
    client.get("/records/100", headers={"X-Subject": "attacker_7"})
    res = client.get("/risk/attacker_7")
    assert res.json()["score"] > 0
    assert "unique_denied_short" in res.json()["contributions"]

def test_17_max_100_cap():
    subject = "attacker_8"
    now = time.time()
    for i in range(20):
        engine.history[subject].append(Event(900+i, False, now, "records"))
    res = client.get("/risk/attacker_8")
    assert res.json()["score"] == 100

def test_18_blocking():
    for i in range(1000, 1020):
        res = client.get(f"/records/{i}", headers={"X-Subject": "attacker_9"})
    assert res.status_code == 403
    assert res.json()["detail"]["outcome"] == "blocked"

def test_19_post_blocking():
    engine.blocked_until["attacker_10"] = time.time() + 300
    res = client.get("/records/10", headers={"X-Subject": "attacker_10"})
    assert res.status_code == 403
    assert res.json()["detail"]["outcome"] == "blocked"

def test_20_history_cleanup():
    subject = "attacker_11"
    now = time.time()
    engine.history[subject].append(Event(50, False, now - 4000, "records"))
    engine.cleanup_stale()
    assert subject not in engine.history

def test_21_endpoint_diversity():
    client.get("/users/1", headers={"X-Subject": "attacker_12"})
    client.get("/invoices/1", headers={"X-Subject": "attacker_12"})
    res = client.get("/risk/attacker_12")
    assert "endpoint_diversity" in res.json()["signals"]

def test_22_global_aggregation():
    # Insert users into DB
    with db() as c:
        for i in range(55):
            c.execute("INSERT OR IGNORE INTO users VALUES (?, ?)", (f"dummy_{i}", "customer"))
    for i in range(55):
        client.get("/records/999", headers={"X-Subject": f"dummy_{i}"})
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
