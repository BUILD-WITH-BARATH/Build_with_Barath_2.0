"""Reproducible benchmark runner for the BOLA dual-layer defense.

Exercises the scenarios described in EXTERNAL_VALIDATION.md against an in-process
TestClient (no server needs to be running) and writes machine-checkable evidence to
./results/:

  - events.csv        every request issued by this run, one row each
  - metrics.json       pass/fail per scenario plus aggregate detection metrics
  - warmup_curve.csv   risk score after each successive unauthorized request from a
                        fresh identity, showing how many requests the detector needs
                        before it escalates Normal -> Suspicious -> High Risk -> Attack

Run with:  python benchmark.py   (from inside bola-benchmark/, after `pip install -r requirements.txt`)
"""
from __future__ import annotations

import csv
import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

from app import app, db, engine

RESULTS_DIR = Path(__file__).with_name("results")
client = TestClient(app)
events: list[dict] = []


def call(scenario: str, method: str, path: str, subject: str | None = None) -> dict:
    headers = {"X-Subject": subject} if subject else {}
    started = time.perf_counter()
    response = client.request(method, path, headers=headers)
    elapsed_ms = (time.perf_counter() - started) * 1000
    try:
        body = response.json()
    except ValueError:
        body = {}
    row = {
        "scenario": scenario,
        "method": method,
        "path": path,
        "subject": subject or "",
        "status_code": response.status_code,
        "decision": response.headers.get("X-Detector-Decision", ""),
        "risk_score": response.headers.get("X-Risk-Score", ""),
        "risk_category": response.headers.get("X-Risk-Category", ""),
        "latency_ms": round(elapsed_ms, 3),
    }
    events.append(row)
    return {"response": response, "body": body, **row}


def reset() -> None:
    client.post("/reset")


def run_scenarios() -> list[dict]:
    checks = []

    def expect(name: str, condition: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(condition), "detail": detail})

    # 1. Owner access
    reset()
    r = call("owner_access", "GET", "/records/1", "alice")
    expect("owner_access_allowed", r["status_code"] == 200, f"status={r['status_code']}")

    # 2. Assigned (doctor) access
    reset()
    r = call("assigned_access", "GET", "/records/1", "dr_singh")
    expect("assigned_access_allowed", r["status_code"] == 200, f"status={r['status_code']}")

    # 3. Active delegation
    reset()
    r = call("delegated_access", "GET", "/records/17", "support_amy")
    delegation = r["body"].get("delegation") or {}
    expect("delegated_access_allowed", r["status_code"] == 200, f"status={r['status_code']}")
    expect(
        "delegation_shows_reason_approver_expiry",
        all(k in delegation for k in ("reason", "approved_by", "seconds_remaining")),
        f"delegation={delegation}",
    )

    # 4. Expired delegation must be denied
    reset()
    with db() as c:
        c.execute(
            "INSERT INTO access_grants VALUES (?, ?, ?, ?, ?)",
            ("support_amy", 42, time.time() - 3600, "expired-ticket", "security_admin"),
        )
    r = call("expired_delegation", "GET", "/records/42", "support_amy")
    expect("expired_delegation_denied", r["status_code"] == 403, f"status={r['status_code']}")

    # 5. Straight denial (owned by someone else) must not leak record data or existence
    reset()
    r_exists = call("denied_existing_record", "GET", "/records/99", "alice")
    r_missing = call("denied_missing_record", "GET", "/records/999999", "alice")
    same_explanation = (
        r_exists["body"].get("detail", {}).get("explanations")
        == r_missing["body"].get("detail", {}).get("explanations")
    )
    expect("denied_no_record_data_leak", "record" not in r_exists["body"], f"body_keys={list(r_exists['body'].keys())}")
    expect(
        "denied_no_existence_oracle",
        same_explanation,
        "existing vs missing record produced identical denial explanations" if same_explanation else "explanations differed - existence oracle present",
    )

    # 6. Legitimate rapid burst by the true owner must not raise risk (no false positive)
    reset()
    for i in range(1, 11):
        call("legitimate_burst", "GET", f"/records/{i}", "alice")
    risk = client.get("/risk/alice").json()
    expect("legitimate_burst_zero_risk", risk["score"] == 0, f"score={risk['score']}")

    # 7. Rapid BOLA fuzzing across unauthorized IDs
    reset()
    for i in range(51, 56):
        call("rapid_bola", "GET", f"/records/{i}", "attacker_1")
    risk = client.get("/risk/attacker_1").json()
    expect(
        "rapid_bola_flagged",
        "unauthorized_unique_object_pressure" in risk["signals"],
        f"signals={risk['signals']}, score={risk['score']}",
    )

    # 8. Sequential ID enumeration
    reset()
    for i in [300, 301, 302, 303]:
        call("sequential_enumeration", "GET", f"/records/{i}", "attacker_2")
    risk = client.get("/risk/attacker_2").json()
    expect(
        "sequential_enumeration_flagged",
        "sequential_id_enumeration" in risk["signals"],
        f"signals={risk['signals']}",
    )

    # 9. Low-and-slow reconnaissance via the built-in simulator
    reset()
    r = call("low_and_slow", "POST", "/simulate/low_and_slow")
    expect("low_and_slow_endpoint_ok", r["status_code"] == 200, f"status={r['status_code']}")
    risk = client.get("/risk/attacker_slow").json()
    expect(
        "low_and_slow_flagged",
        "low_and_slow_reconnaissance" in risk["signals"],
        f"signals={risk['signals']}",
    )

    # 10. Coordinated / Sybil attack against a single record
    reset()
    call("coordinated_sybil", "POST", "/simulate/coordinated")
    stats = client.get("/stats").json()
    expect(
        "coordinated_attack_detected",
        len(stats.get("coordinated_attacks", {})) > 0,
        f"coordinated_attacks={stats.get('coordinated_attacks')}",
    )

    # 11. Sustained abuse must trigger an automatic lockout
    reset()
    last = None
    for i in range(2000, 2020):
        last = call("sustained_abuse_lockout", "GET", f"/records/{i}", "attacker_9")
    expect(
        "high_risk_auto_blocked",
        last is not None and last["decision"] == "block",
        f"final_decision={last['decision'] if last else None}",
    )

    return checks


def run_warmup_curve() -> list[dict]:
    """One fresh identity making unauthorized requests one at a time; record the risk
    score after each request to show detection latency (requests-to-escalate)."""
    reset()
    subject = "warmup_curve_subject"
    rows = []
    for step, record_id in enumerate(range(600, 640), start=1):
        r = client.get(f"/records/{record_id}", headers={"X-Subject": subject})
        risk = client.get(f"/risk/{subject}").json()
        rows.append(
            {
                "step": step,
                "record_id": record_id,
                "status_code": r.status_code,
                "score": risk["score"],
                "category": risk["category"],
                "signals": "|".join(risk["signals"]),
            }
        )
        if engine.blocked_until.get(subject, 0) > time.time():
            break
    return rows


def main() -> None:
    RESULTS_DIR.mkdir(exist_ok=True)

    checks = run_scenarios()
    warmup_rows = run_warmup_curve()

    with (RESULTS_DIR / "events.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(events[0].keys()))
        writer.writeheader()
        writer.writerows(events)

    with (RESULTS_DIR / "warmup_curve.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(warmup_rows[0].keys()))
        writer.writeheader()
        writer.writerows(warmup_rows)

    passed = sum(1 for c in checks if c["passed"])
    metrics = {
        "generated_at_unix": time.time(),
        "scenario_checks": checks,
        "scenarios_passed": passed,
        "scenarios_total": len(checks),
        "requests_to_first_block": next(
            (row["step"] for row in warmup_rows if row["category"] == "Attack"), None
        ),
        "note": "Synthetic in-process benchmark. Not a substitute for independent review - see EXTERNAL_VALIDATION.md.",
    }
    (RESULTS_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"Scenarios passed: {passed}/{len(checks)}")
    for c in checks:
        status = "PASS" if c["passed"] else "FAIL"
        print(f"  [{status}] {c['name']}: {c['detail']}")
    print(f"\nResults written to {RESULTS_DIR}/")


if __name__ == "__main__":
    main()
