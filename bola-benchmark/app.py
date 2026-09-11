"""Minimal FastAPI API with authoritative object authorization and graph telemetry."""
from __future__ import annotations

import sqlite3
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware

DB_PATH = Path(__file__).with_name("demo.db")


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def seed_database() -> None:
    """Resettable, deterministic demo data: users, records, assignments and grants."""
    with db() as c:
        c.executescript(
            """
            DROP TABLE IF EXISTS audit_events;
            DROP TABLE IF EXISTS access_grants;
            DROP TABLE IF EXISTS assignments;
            DROP TABLE IF EXISTS records;
            DROP TABLE IF EXISTS users;
            CREATE TABLE users (id TEXT PRIMARY KEY, role TEXT NOT NULL);
            CREATE TABLE records (id INTEGER PRIMARY KEY, owner_id TEXT NOT NULL, data TEXT NOT NULL);
            CREATE TABLE assignments (subject_id TEXT NOT NULL, record_id INTEGER NOT NULL,
                                      PRIMARY KEY(subject_id, record_id));
            CREATE TABLE access_grants (subject_id TEXT NOT NULL, record_id INTEGER NOT NULL,
                                        expires_at REAL NOT NULL, reason TEXT NOT NULL, approved_by TEXT NOT NULL,
                                        PRIMARY KEY(subject_id, record_id));
            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at REAL NOT NULL,
                subject_id TEXT NOT NULL,
                record_id INTEGER NOT NULL,
                authorization TEXT,
                detector_decision TEXT NOT NULL,
                outcome TEXT NOT NULL,
                explanation TEXT NOT NULL
            );
            """
        )
        users = [("alice", "customer"), ("bob", "customer"), ("dr_singh", "doctor"),
                 ("dr_lee", "doctor"), ("dr_cover", "doctor"), ("support_amy", "support"), ("attacker", "customer"),
                 ("attacker_slow", "customer"), ("security_admin", "security_admin")] + [(f"attacker_{j}", "customer") for j in range(1, 11)] + [(f"sybil_{j}", "customer") for j in range(1, 51)]
        c.executemany("INSERT INTO users VALUES (?, ?)", users)
        records = [(i, "alice" if i <= 50 else "bob", f"confidential record {i}") for i in range(1, 101)]
        c.executemany("INSERT INTO records VALUES (?, ?, ?)", records)
        c.executemany("INSERT INTO assignments VALUES (?, ?)", [("dr_singh", i) for i in range(1, 26)])
        c.executemany("INSERT INTO assignments VALUES (?, ?)", [("dr_lee", i) for i in range(26, 51)])
        # A time-bound delegated/shared record: this must look legitimate to the detector.
        c.execute("INSERT INTO access_grants VALUES (?, ?, ?, ?, ?)",
                  ("support_amy", 17, time.time() + 3600, "ticket-8431", "security_admin"))
        c.executemany("INSERT INTO access_grants VALUES (?, ?, ?, ?, ?)", [
            ("dr_cover", 8, time.time() + 1800, "shift-cover-ward-a", "security_admin"),
            ("dr_cover", 31, time.time() + 1800, "shift-cover-ward-b", "security_admin"),
        ])


def authorization_context(subject: str, record_id: int) -> dict:
    """Authoritative policy. The learned graph is never an authorization source."""
    with db() as c:
        DENY_EXPLANATION = "Access denied: you are not the owner, are not assigned, and have no active delegation."
        record = c.execute("SELECT owner_id FROM records WHERE id = ?", (record_id,)).fetchone()
        if not record:
            # Deliberately identical to the "exists but denied" message below: a distinguishable
            # response would let a caller use record existence as a pre-authorization oracle.
            return {"authorization": None, "explanations": [DENY_EXPLANATION], "delegation": None}
        if record["owner_id"] == subject:
            return {"authorization": "owner", "explanations": ["Access allowed: you own this record."], "delegation": None}
        if c.execute("SELECT 1 FROM assignments WHERE subject_id = ? AND record_id = ?", (subject, record_id)).fetchone():
            return {"authorization": "assigned", "explanations": ["Access allowed: you are assigned to this record."], "delegation": None}
        grant = c.execute("SELECT expires_at, reason, approved_by FROM access_grants WHERE subject_id = ? AND record_id = ?",
                          (subject, record_id)).fetchone()
        if grant and grant["expires_at"] > time.time():
            seconds_remaining = max(0, int(grant["expires_at"] - time.time()))
            return {"authorization": "delegated",
                    "explanations": ["Access allowed: a time-bound delegation is active.",
                                     f"Delegation reason: {grant['reason']}.",
                                     f"Approved by: {grant['approved_by']}.",
                                     f"Access remaining: {seconds_remaining} seconds."],
                    "delegation": {"reason": grant["reason"], "approved_by": grant["approved_by"],
                                   "expires_at_unix": round(grant["expires_at"], 3), "seconds_remaining": seconds_remaining}}
        if grant:
            return {"authorization": None, "explanations": ["Access denied: your delegated permission has expired."], "delegation": None}
    return {"authorization": None, "explanations": [DENY_EXPLANATION], "delegation": None}


def record_audit(subject: str, record_id: int, authorization: str | None, decision: str, outcome: str, explanations: list[str]) -> None:
    with db() as c:
        c.execute("INSERT INTO audit_events (occurred_at, subject_id, record_id, authorization, detector_decision, outcome, explanation) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (time.time(), subject, record_id, authorization, decision, outcome, " | ".join(explanations)))


@dataclass
class Event:
    record_id: int
    allowed: bool
    at: float
    endpoint: str = "records"


class BehavioralRiskEngine:
    def __init__(self, short_window: float = 30.0, long_window: float = 3600.0, block_duration: float = 120.0, rapid_threshold: int = 4, slow_threshold: int = 15):
        self.short_window = short_window
        self.long_window = long_window
        self.block_duration = block_duration
        self.rapid_threshold = rapid_threshold
        self.slow_threshold = slow_threshold
        self.history: dict[str, deque[Event]] = defaultdict(deque)
        self.blocked_until: dict[str, float] = {}
        self.strikes: dict[str, list[float]] = defaultdict(list)
        self.pending_permanent_bans: set[str] = set()
        self.approved_permanent_bans: set[str] = set()
        self.global_record_tracker: dict[int, set[str]] = defaultdict(set)

    def get_strike_count(self, subject: str, now: float | None = None) -> int:
        now = now or time.time()
        valid_strikes = [t for t in self.strikes[subject] if now - t <= self.long_window]
        self.strikes[subject] = valid_strikes
        return len(valid_strikes)

    def register_strike_and_block(self, subject: str, now: float) -> tuple[float, str, int]:
        """Registers a new strike within the 1-hour window and escalates the penalty."""
        self.get_strike_count(subject, now)
        self.strikes[subject].append(now)
        count = len(self.strikes[subject])
        
        if count == 1:
            lockout = 120.0 # Strike 1: 2-Minute Soft Lockout
            signal = "strike_1_soft_lockout_2m"
        elif count == 2:
            lockout = 1800.0 # Strike 2: 30-Minute Hard Lockout
            signal = "strike_2_hard_lockout_30m"
        else:
            if subject in self.approved_permanent_bans:
                lockout = 315360000.0 # Permanent Ban (10 years)
                signal = "strike_3_permanent_ban_approved"
            else:
                # 🚨 Strike 3 requires Admin Approval: Place in temporary holding quarantine (30m) pending admin review
                self.pending_permanent_bans.add(subject)
                lockout = 1800.0
                signal = "strike_3_pending_admin_approval"
            
        self.blocked_until[subject] = now + lockout
        return lockout, signal, count

    def approve_permanent_ban(self, subject: str, now: float | None = None) -> bool:
        now = now or time.time()
        self.pending_permanent_bans.discard(subject)
        self.approved_permanent_bans.add(subject)
        self.blocked_until[subject] = now + 315360000.0
        return True

    def reject_permanent_ban(self, subject: str, now: float | None = None) -> bool:
        now = now or time.time()
        self.pending_permanent_bans.discard(subject)
        self.approved_permanent_bans.discard(subject)
        if self.strikes[subject]:
            self.strikes[subject].pop()
        self.blocked_until[subject] = now + 60.0
        return True

    def cleanup_stale(self) -> None:
        now = time.time()
        stale_subjects = []
        for subject, q in self.history.items():
            if not q or now - q[-1].at > self.long_window:
                stale_subjects.append(subject)
        for subject in stale_subjects:
            del self.history[subject]
            if subject in self.blocked_until and self.blocked_until[subject] < now:
                del self.blocked_until[subject]

    def reset(self) -> None:
        self.history.clear()
        self.blocked_until.clear()
        self.strikes.clear()
        self.pending_permanent_bans.clear()
        self.approved_permanent_bans.clear()
        self.global_record_tracker.clear()

    def evaluate(self, subject: str, record_id: int, allowed: bool, endpoint: str = "records") -> tuple[str, list[str], bool, int, str]:
        now = time.time()
        
        if not allowed:
            self.global_record_tracker[record_id].add(subject)
            
        # Check if currently blocked
        if self.blocked_until.get(subject, 0) > now:
            strike_count = self.get_strike_count(subject, now)
            if subject in self.approved_permanent_bans:
                sig = "strike_3_permanent_ban_approved"
            elif subject in self.pending_permanent_bans or strike_count >= 3:
                sig = "strike_3_pending_admin_approval"
            elif strike_count == 2:
                sig = "strike_2_hard_lockout_30m"
            else:
                sig = "strike_1_soft_lockout_2m"
            return "block", ["temporarily_blocked", sig], False, 100, "Attack"

        # prune long history
        q = self.history[subject]
        while q and now - q[0].at > self.long_window:
            q.popleft()
            
        q.append(Event(record_id, allowed, now, endpoint))
        
        score_data = self.compute_risk(subject, now)
        score, signals, category = score_data["score"], score_data["signals"], score_data["category"]
        
        unseen = False # Kept for compatibility if necessary
        decision = "allow" if allowed else "deny"
        if score >= 90:
            decision = "block"
            lockout, strike_sig, count = self.register_strike_and_block(subject, now)
            signals.append("blocked_due_to_high_risk")
            signals.append(strike_sig)
            
        return decision, signals, unseen, score, category

    def compute_risk(self, subject: str, now: float) -> dict:
        q = self.history[subject]
        
        denied_all = [e for e in q if not e.allowed]
        denied_short = [e for e in denied_all if now - e.at <= self.short_window]
        
        unique_denied_short = len({e.record_id for e in denied_short if e.endpoint == "records"})
        unique_denied_long = len({e.record_id for e in denied_all if e.endpoint == "records"})
        
        total_long = len(q)
        failed_long = len(denied_all)
        
        signals = []
        contributions = {}
        
        if unique_denied_short >= self.rapid_threshold:
            contributions["unauthorized_unique_object_pressure"] = 45
            signals.append("unauthorized_unique_object_pressure")
        elif unique_denied_short > 0:
            contributions["unique_denied_short"] = unique_denied_short * 10
            
        # Sequential short
        short_ids = [e.record_id for e in q if (not e.allowed) and (now - e.at <= self.short_window) and e.endpoint == "records"]
        sequential_steps = sum(1 for a, b in zip(short_ids, short_ids[1:]) if abs(b - a) == 1)
        if sequential_steps >= 2:
            contributions["sequential_id_enumeration"] = 35
            signals.append("sequential_id_enumeration")
            
        if unique_denied_long >= self.slow_threshold:
            contributions["low_and_slow_reconnaissance"] = 50
            signals.append("low_and_slow_reconnaissance")
        elif unique_denied_long > 0:
            contributions["unique_denied_long"] = unique_denied_long * 2
            
        if total_long > 0:
            ratio = failed_long / total_long
            if ratio > 0.5 and failed_long > 5:
                contributions["high_failure_ratio"] = 20
                signals.append("high_failure_ratio")

        endpoints_hit = len({e.endpoint for e in denied_all})
        if endpoints_hit >= 2:
            contributions["endpoint_diversity"] = 20
            signals.append("endpoint_diversity")
                
        score = min(100, sum(contributions.values()))
        
        if self.blocked_until.get(subject, 0) > now:
            score = 100
            if "temporarily_blocked" not in signals:
                signals.append("temporarily_blocked")
            strike_count = self.get_strike_count(subject, now)
            if subject in self.approved_permanent_bans:
                if "strike_3_permanent_ban_approved" not in signals:
                    signals.append("strike_3_permanent_ban_approved")
            elif subject in self.pending_permanent_bans or strike_count >= 3:
                if "strike_3_pending_admin_approval" not in signals:
                    signals.append("strike_3_pending_admin_approval")
            elif strike_count == 2 and "strike_2_hard_lockout_30m" not in signals:
                signals.append("strike_2_hard_lockout_30m")
            elif strike_count == 1 and "strike_1_soft_lockout_2m" not in signals:
                signals.append("strike_1_soft_lockout_2m")
            category = "Attack"
        elif score < 40:
            category = "Normal"
        elif score < 70:
            category = "Suspicious"
        elif score < 90:
            category = "High Risk"
        else:
            category = "Attack"
            
        return {"score": score, "signals": signals, "category": category, "contributions": contributions}


engine = BehavioralRiskEngine()
app = FastAPI(title="BOLA Graph Benchmark")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def explain_detector_signals(signals: list[str]) -> list[str]:
    messages = {
        "unauthorized_unique_object_pressure": "You requested four or more different records without permission within 30 seconds.",
        "sequential_id_enumeration": "Your requests followed a sequential record-ID guessing pattern.",
        "low_and_slow_reconnaissance": "You made 15 or more unauthorized requests over a prolonged period (low-and-slow reconnaissance).",
        "high_failure_ratio": "You have a high ratio of failed to successful requests.",
        "endpoint_diversity": "You have triggered unauthorized access across multiple API endpoints.",
        "temporarily_blocked": "Your identity has been temporarily blocked due to malicious behavior.",
        "blocked_due_to_high_risk": "Your risk score reached the Attack threshold and you are now blocked.",
        "strike_1_soft_lockout_2m": "Strike 1/3: 2-Minute Soft Lockout penalty enforced.",
        "strike_2_hard_lockout_30m": "Strike 2/3: Repeat violation within 1 hour. 30-Minute Hard Lockout penalty enforced.",
        "strike_3_pending_admin_approval": "Strike 3/3 Reached: Permanent Ban PENDING ADMIN APPROVAL (Quarantined).",
        "strike_3_permanent_ban_approved": "Strike 3/3: Permanent Firewall Blacklist APPROVED by Administrator."
    }
    return [messages[s] for s in signals if s in messages]


@app.post("/reset")
def reset() -> dict:
    seed_database()
    engine.reset()
    return {"status": "reset"}


soc_alerts: list[dict] = []

def dispatch_soc_alert(subject: str, record_id: int, score: int, category: str, signals: list[str]) -> dict:
    """Dispatches a structured forensic payload to SIEM/SOC and appends to in-memory audit queue."""
    strikes = max(1, engine.get_strike_count(subject))
    tier = "PERMANENT_BLACKLIST" if strikes >= 3 else ("HARD_LOCKOUT_30M" if strikes == 2 else "SOFT_LOCKOUT_2M")
    mitigation = "PERMANENT_IDENTITY_BLACKLIST (Strike 3/3)" if strikes >= 3 else ("AUTOMATIC_IDENTITY_LOCKOUT_30M (Strike 2/3)" if strikes == 2 else "AUTOMATIC_IDENTITY_LOCKOUT_120S (Strike 1/3)")
    
    alert_payload = {
        "alert_id": f"SOC-ALERT-{int(time.time() * 1000)}",
        "timestamp": time.time(),
        "severity": "CRITICAL" if (score >= 90 or strikes >= 2) else "HIGH",
        "threat_type": "BOLA_ENUMERATION_ATTACK",
        "attacker_identity": subject,
        "targeted_record_id": record_id,
        "risk_score": score,
        "risk_category": category,
        "signals_tripped": signals,
        "strike_level": f"Strike {min(strikes, 3)}/3",
        "escalation_tier": tier,
        "mitigation_action": mitigation,
        "recommended_secops_action": f"Revoke active OAuth token for '{subject}' and isolate network source." if strikes < 3 else f"PERMANENTLY BAN '{subject}' and revoke all credentials."
    }
    soc_alerts.insert(0, alert_payload)
    if len(soc_alerts) > 50:
        soc_alerts.pop()
        
    return alert_payload


@app.get("/records/{record_id}")
def get_record(record_id: int, response: Response,
               x_subject: str | None = Header(default=None)) -> dict:
    subject = x_subject
    if not subject:
        raise HTTPException(401, "Missing X-Subject")
    with db() as c:
        if not c.execute("SELECT 1 FROM users WHERE id = ?", (subject,)).fetchone():
            # Auto-register new users for the demo so any name works
            c.execute("INSERT INTO users VALUES (?, 'customer')", (subject,))
            c.commit()
    
    access = authorization_context(subject, record_id)
    authorization = access["authorization"]
    
    decision, signals, unseen, score, category = engine.evaluate(subject, record_id, authorization is not None)
    detector_explanations = explain_detector_signals(signals)
    explanations = access["explanations"] + detector_explanations
    
    response.headers["X-Detector-Decision"] = decision
    response.headers["X-Detector-Signals"] = ",".join(signals)
    response.headers["X-Graph-Unseen"] = str(unseen).lower()
    response.headers["X-Risk-Score"] = str(score)
    response.headers["X-Risk-Category"] = category
    
    if decision == "block":
        explanations = ["Access blocked: BOLA-style behavior was detected."] + explanations
        record_audit(subject, record_id, authorization, decision, "blocked", explanations)
        # 🚨 Trigger Real-Time SOC Incident Alert
        dispatch_soc_alert(subject, record_id, score, category, signals)
        raise HTTPException(403, detail={"outcome": "blocked", "reason": "BOLA-style behavior detected", "signals": signals,
                                         "explanations": explanations, "score": score, "category": category,
                                         "soc_alert_dispatched": True},
                            headers={"X-Detector-Decision": decision, "X-Detector-Signals": ",".join(signals),
                                     "X-Graph-Unseen": str(unseen).lower(), "X-Risk-Score": str(score), "X-Risk-Category": category})
    if authorization is None:
        record_audit(subject, record_id, authorization, decision, "denied", explanations)
        raise HTTPException(403, detail={"outcome": "denied", "reason": "No valid object-level authorization", "explanations": explanations, "score": score, "category": category},
                            headers={"X-Detector-Decision": decision, "X-Detector-Signals": ",".join(signals),
                                     "X-Graph-Unseen": str(unseen).lower(), "X-Risk-Score": str(score), "X-Risk-Category": category})
    with db() as c:
        row = c.execute("SELECT id, owner_id, data FROM records WHERE id = ?", (record_id,)).fetchone()
    record_audit(subject, record_id, authorization, decision, "allowed", explanations)
    return {"record": dict(row), "authorization": authorization, "graph_edge_known": not unseen,
            "delegation": access["delegation"], "decision": {"outcome": "allowed", "explanations": explanations},
            "score": score, "category": category}


@app.get("/audit-events")
def get_audit_events(x_subject: str | None = Header(default=None)) -> dict:
    if x_subject != "security_admin":
        raise HTTPException(403, "Audit access requires the security_admin subject")
    with db() as c:
        rows = c.execute("SELECT id, occurred_at, subject_id, record_id, authorization, detector_decision, outcome, explanation FROM audit_events ORDER BY id DESC LIMIT 100").fetchall()
    return {"events": [dict(row) for row in rows]}


@app.post("/simulate/normal")
def simulate_normal() -> dict:
    from fastapi.testclient import TestClient
    client = TestClient(app)
    results = []
    # Alice requests her own records 1 to 50
    for i in range(1, 51):
        res = client.get(f"/records/{i}", headers={"X-Subject": "alice"})
        results.append(res.status_code)
    return {"status": "normal_simulated", "requests": 50, "results": results}

@app.post("/simulate/rapid")
def simulate_rapid() -> dict:
    from fastapi.testclient import TestClient
    client = TestClient(app)
    results = []
    # Attacker rapidly asks for ids 51 to 55
    for i in range(51, 56):
        res = client.get(f"/records/{i}", headers={"X-Subject": "attacker_1"})
        results.append({"id": i, "status": res.status_code, "risk": res.headers.get("X-Risk-Score"), "category": res.headers.get("X-Risk-Category")})
    return {"status": "rapid_simulated", "results": results}

@app.post("/simulate/low_and_slow")
def simulate_low_and_slow() -> dict:
    from fastapi.testclient import TestClient
    import time
    client = TestClient(app)
    results = []
    
    subject = "attacker_slow"
    now = time.time()
    
    # Generate 15 failed requests spaced over the hour
    for i in range(15):
        event_time = now - (3600) + (i * 240)
        engine.history[subject].append(Event(50+i, False, event_time))
        record_audit(subject, 50+i, None, "deny", "denied", ["Simulated low and slow deny"])
        
    res = client.get(f"/records/66", headers={"X-Subject": subject})
    results.append({"status": res.status_code, "risk": res.headers.get("X-Risk-Score"), "category": res.headers.get("X-Risk-Category")})
    return {"status": "low_and_slow_simulated", "results": results}

@app.post("/simulate/coordinated")
def simulate_coordinated() -> dict:
    from fastapi.testclient import TestClient
    client = TestClient(app)
    # Simulate 50 sybils hitting record 1
    for i in range(1, 51):
        client.get("/records/1", headers={"X-Subject": f"sybil_{i}"})
    return {"status": "coordinated_simulated"}


@app.get("/users/{user_id}")
def get_user(user_id: int, response: Response, x_subject: str | None = Header(default=None)) -> dict:
    if not x_subject:
        raise HTTPException(401, "Missing X-Subject")
    decision, signals, unseen, score, category = engine.evaluate(x_subject, user_id, False, endpoint="users")
    if decision == "block":
        raise HTTPException(403, detail={"outcome": "blocked", "score": score, "category": category})
    raise HTTPException(403, detail={"outcome": "denied", "score": score, "category": category})

@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: int, response: Response, x_subject: str | None = Header(default=None)) -> dict:
    if not x_subject:
        raise HTTPException(401, "Missing X-Subject")
    decision, signals, unseen, score, category = engine.evaluate(x_subject, invoice_id, False, endpoint="invoices")
    if decision == "block":
        raise HTTPException(403, detail={"outcome": "blocked", "score": score, "category": category})
    raise HTTPException(403, detail={"outcome": "denied", "score": score, "category": category})

@app.get("/config")
def get_config() -> dict:
    return {
        "short_window": engine.short_window,
        "long_window": engine.long_window,
        "rapid_threshold": engine.rapid_threshold,
        "slow_threshold": engine.slow_threshold,
        "strike_1_duration": "2m (Soft)",
        "strike_2_duration": "30m (Hard)",
        "strike_3_duration": "Permanent (Blacklist)"
    }

@app.get("/stats")
def get_stats() -> dict:
    engine.cleanup_stale()
    blocked = len([k for k, v in engine.blocked_until.items() if v > time.time()])
    coordinated = {record_id: len(subjects) for record_id, subjects in engine.global_record_tracker.items() if len(subjects) >= 50}
    return {"active_subjects": len(engine.history), "blocked_subjects": blocked, "coordinated_attacks": coordinated}

@app.get("/events")
def get_events(x_subject: str | None = Header(default=None)) -> dict:
    # Same audit data as /audit-events (kept for backward compatibility); must carry the same gate.
    if x_subject != "security_admin":
        raise HTTPException(403, "Audit access requires the security_admin subject")
    with db() as c:
        rows = c.execute("SELECT id, occurred_at, subject_id, record_id, authorization, detector_decision, outcome, explanation FROM audit_events ORDER BY id DESC LIMIT 50").fetchall()
    return {"events": [dict(row) for row in rows]}

@app.get("/risk/{subject}")
def get_risk(subject: str) -> dict:
    now = time.time()
    res = engine.compute_risk(subject, now)
    strikes = engine.get_strike_count(subject, now)
    is_blocked = engine.blocked_until.get(subject, 0) > now
    remaining = int(engine.blocked_until[subject] - now) if is_blocked else 0
    is_pending = subject in engine.pending_permanent_bans or (strikes >= 3 and subject not in engine.approved_permanent_bans and is_blocked)
    is_approved = subject in engine.approved_permanent_bans or (is_blocked and remaining > 86400 * 30)
    return {
        "subject": subject,
        "score": res["score"],
        "category": res["category"],
        "signals": res["signals"],
        "contributions": res["contributions"],
        "strikes": strikes,
        "is_blocked": is_blocked,
        "is_pending_ban": is_pending,
        "is_approved_ban": is_approved,
        "is_permanent": is_approved,
        "lockout_remaining_s": remaining
    }


@app.post("/admin/approve-ban/{subject}")
def approve_permanent_ban_endpoint(subject: str) -> dict:
    """Admin approves permanent firewall ban for Strike 3 offender."""
    engine.approve_permanent_ban(subject)
    record_audit(subject, 0, "ADMIN_AUTHORITY", "block", "blocked", [f"Admin APPROVED Permanent Firewall Ban for '{subject}'"])
    return {"status": "permanent_ban_approved", "subject": subject, "is_permanent": True}


@app.post("/admin/reject-ban/{subject}")
def reject_permanent_ban_endpoint(subject: str) -> dict:
    """Admin dismisses permanent ban and relaxes penalty for false-positive or pentester."""
    engine.reject_permanent_ban(subject)
    record_audit(subject, 0, "ADMIN_AUTHORITY", "allow", "allowed", [f"Admin DISMISSED Permanent Ban for '{subject}' (Quarantine Relaxed)"])
    return {"status": "ban_dismissed", "subject": subject, "is_permanent": False}


@app.get("/admin/pending-bans")
def get_pending_bans() -> dict:
    """Returns all subjects currently awaiting administrative ban approval."""
    return {
        "pending_bans": list(engine.pending_permanent_bans),
        "approved_bans": list(engine.approved_permanent_bans)
    }


@app.get("/soc/alerts")
def get_soc_alerts() -> dict:
    """Returns real-time forensic alerts dispatched to the SOC / SIEM."""
    return {
        "total_alerts": len(soc_alerts),
        "recent_alerts": soc_alerts[:20]
    }


@app.post("/soc/test-webhook")
def test_soc_webhook(payload: dict | None = None) -> dict:
    """Trigger or receive external SOC alert webhook and log to audit events."""
    if not payload:
        payload = dispatch_soc_alert(
            subject="simulated_adversary",
            record_id=999,
            score=100,
            category="Attack",
            signals=["unauthorized_unique_object_pressure", "sequential_id_enumeration", "manual_test"]
        )
    else:
        # Record into audit events table so it appears in live frontend dashboard
        subject = payload.get("attacker_identity", "external_attacker")
        target_id = payload.get("targeted_object_id", 0)
        signals = payload.get("signals_tripped", ["bola_attempt"])
        decision = payload.get("decision", "deny")
        outcome = "blocked" if decision == "block" else "denied"
        explanation = f"Django BOLA Activity: {','.join(signals)}" if outcome == "blocked" else f"Django Object Denied: Attempted {target_id}"
        
        # Feed into behavioral risk engine so /risk/{subject} and /stats reflect it
        engine.history[subject].append(Event(target_id, False, time.time(), "records"))
        if decision == "block":
            lockout, strike_sig, count = engine.register_strike_and_block(subject, time.time())
            if strike_sig not in signals:
                signals.append(strike_sig)
            score = payload.get("risk_score", 100)
            category = payload.get("risk_category", "Attack")
            dispatch_soc_alert(subject, target_id, score, category, signals)
            
        record_audit(subject, target_id, None, decision, outcome, [explanation])
    return {"status": "alert_logged_and_synced", "payload": payload}


seed_database()
