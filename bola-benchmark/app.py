"""Multi-tenant FastAPI API with authoritative object authorization and graph telemetry.

Backed by Postgres (not SQLite) so it can run as a real, horizontally-scaled
service shared by multiple customers ("tenants"), each isolated by tenant_id.
Two front doors:
  - The JWT-authenticated demo/dashboard API (unchanged in spirit from before),
    scoped to a single seeded "demo" tenant.
  - The API-key-authenticated product API (/v1/*) other companies' backends
    call on every request instead of hosting their whole API through us.
"""
from __future__ import annotations

import atexit
import hashlib
import os
import secrets
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import bcrypt
import jwt
import joblib
import numpy as np
import pandas as pd
import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sklearn.ensemble import IsolationForest
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# --- Configuration (env-overridable; defaults are dev-only, never use these in production) ---
APP_ENV = os.environ.get("APP_ENV", "dev")
DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() != "false"
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-insecure-secret-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = int(os.environ.get("JWT_EXPIRY_SECONDS", "3600"))
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "changeme123")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin_changeme123")
ADMIN_ROLE = "security_admin"
DEMO_TENANT_ID = "demo"
TENANT_SIGNUP_KEY = os.environ.get("TENANT_SIGNUP_KEY", "dev-insecure-signup-key-change-in-production")

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is required (Postgres connection string) - this app no longer runs on "
        "SQLite. For local dev, point it at a free hosted Postgres (e.g. Neon, Supabase) or a "
        "local Postgres instance."
    )

if APP_ENV == "prod":
    _insecure_defaults = []
    if JWT_SECRET.startswith("dev-"):
        _insecure_defaults.append("JWT_SECRET")
    if DEMO_PASSWORD == "changeme123":
        _insecure_defaults.append("DEMO_PASSWORD")
    if ADMIN_PASSWORD == "admin_changeme123":
        _insecure_defaults.append("ADMIN_PASSWORD")
    if TENANT_SIGNUP_KEY.startswith("dev-"):
        _insecure_defaults.append("TENANT_SIGNUP_KEY")
    if _insecure_defaults:
        raise RuntimeError(
            f"APP_ENV=prod but dev-only defaults still set for: {', '.join(_insecure_defaults)}. "
            "Set real values via environment variables before running in production."
        )
    if not os.environ.get("FRONTEND_ORIGIN"):
        raise RuntimeError(
            "APP_ENV=prod requires FRONTEND_ORIGIN (comma-separated allowed origins) to be set explicitly - "
            "refusing to boot with an unset CORS policy rather than silently blocking (or wildcarding) all origins."
        )


def build_anomaly_model() -> IsolationForest:
    """Unsupervised ML layer: flags behavior patterns statistically unlike normal
    traffic, as a complement to the fixed-threshold heuristics in compute_risk().
    Trained once at startup on synthetic feature vectors: [unique_denied_short,
    sequential_steps, unique_denied_long, failure_ratio, endpoints_hit].
    """
    rng = np.random.RandomState(42)

    normal = []
    for _ in range(300):
        normal.append([
            rng.choice([0, 0, 0, 1]),
            0,
            rng.choice([0, 0, 0, 0, 1, 2]),
            rng.uniform(0.0, 0.3),
            rng.choice([0, 0, 1]),
        ])

    attack = []
    for _ in range(60):
        attack.append([
            rng.randint(4, 12),
            rng.randint(2, 6),
            rng.randint(15, 40),
            rng.uniform(0.6, 1.0),
            rng.randint(2, 4),
        ])

    training_data = np.array(normal + attack)
    model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
    model.fit(training_data)
    return model


anomaly_model = build_anomaly_model()

_ENDPOINT_MODEL_PATH = Path(__file__).with_name("models") / "endpoint_anomaly_model.joblib"
endpoint_anomaly_model = joblib.load(_ENDPOINT_MODEL_PATH) if _ENDPOINT_MODEL_PATH.exists() else None


_pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=10, kwargs={"row_factory": dict_row}, open=True)
atexit.register(_pool.close)


@contextmanager
def db():
    with _pool.connection() as connection:
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise


def hash_api_key(key: str) -> str:
    """API keys are high-entropy random tokens (not human passwords), so a fast
    deterministic hash for exact-match lookup is correct here, not bcrypt."""
    return hashlib.sha256(key.encode()).hexdigest()


def generate_api_key() -> str:
    return "sk_" + secrets.token_urlsafe(32)


def init_schema() -> None:
    """Idempotent schema creation. Never drops data - this runs against a real,
    shared, multi-tenant database, not a disposable demo file."""
    with db() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                api_key_hash TEXT NOT NULL,
                created_at DOUBLE PRECISION NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                tenant_id TEXT NOT NULL,
                id TEXT NOT NULL,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                PRIMARY KEY (tenant_id, id)
            );
            CREATE TABLE IF NOT EXISTS records (
                tenant_id TEXT NOT NULL,
                id TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, id)
            );
            CREATE TABLE IF NOT EXISTS assignments (
                tenant_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                record_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, subject_id, record_id)
            );
            CREATE TABLE IF NOT EXISTS access_grants (
                tenant_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                record_id TEXT NOT NULL,
                expires_at DOUBLE PRECISION NOT NULL,
                reason TEXT NOT NULL,
                approved_by TEXT NOT NULL,
                PRIMARY KEY (tenant_id, subject_id, record_id)
            );
            CREATE TABLE IF NOT EXISTS risk_events (
                tenant_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                record_id TEXT NOT NULL,
                allowed BOOLEAN NOT NULL,
                at DOUBLE PRECISION NOT NULL,
                endpoint TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_risk_events_tenant_subject ON risk_events(tenant_id, subject, at);
            CREATE TABLE IF NOT EXISTS risk_strikes (
                tenant_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                at DOUBLE PRECISION NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_risk_strikes_tenant_subject ON risk_strikes(tenant_id, subject, at);
            CREATE TABLE IF NOT EXISTS risk_blocks (
                tenant_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                blocked_until DOUBLE PRECISION NOT NULL,
                PRIMARY KEY (tenant_id, subject)
            );
            CREATE TABLE IF NOT EXISTS risk_bans (
                tenant_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                status TEXT NOT NULL,
                PRIMARY KEY (tenant_id, subject)
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id SERIAL PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                occurred_at DOUBLE PRECISION NOT NULL,
                subject_id TEXT NOT NULL,
                record_id TEXT NOT NULL,
                "authorization" TEXT,
                detector_decision TEXT NOT NULL,
                outcome TEXT NOT NULL,
                explanation TEXT NOT NULL
            );
            """
        )


def seed_demo_tenant(force: bool = False) -> None:
    """Seeds (or, if force=True, wipes-and-reseeds) ONLY the demo tenant's data.
    Never touches any other tenant - this backs the public demo/dashboard and
    the /reset button, not a database-wide reset."""
    demo_hash = bcrypt.hashpw(DEMO_PASSWORD.encode(), bcrypt.gensalt()).decode()
    admin_hash = bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt()).decode()

    with db() as c, c.cursor() as cur:
        if not force:
            existing = cur.execute("SELECT 1 FROM tenants WHERE id = %s", (DEMO_TENANT_ID,)).fetchone()
            if existing:
                return

        for table in ("access_grants", "assignments", "records", "users",
                       "risk_events", "risk_strikes", "risk_blocks", "risk_bans"):
            cur.execute(f"DELETE FROM {table} WHERE tenant_id = %s", (DEMO_TENANT_ID,))

        cur.execute(
            "INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (id) DO NOTHING",
            (DEMO_TENANT_ID, "Demo", hash_api_key("demo-key-unused"), time.time()),
        )

        users = ([("alice", "customer", demo_hash), ("bob", "customer", demo_hash),
                  ("dr_singh", "doctor", demo_hash), ("dr_lee", "doctor", demo_hash),
                  ("dr_cover", "doctor", demo_hash), ("support_amy", "support", demo_hash),
                  ("attacker", "customer", demo_hash), ("attacker_slow", "customer", demo_hash),
                  (ADMIN_ROLE, ADMIN_ROLE, admin_hash)]
                 + [(f"attacker_{j}", "customer", demo_hash) for j in range(1, 11)]
                 + [(f"sybil_{j}", "customer", demo_hash) for j in range(1, 51)])
        cur.executemany(
            "INSERT INTO users (tenant_id, id, role, password_hash) VALUES (%s, %s, %s, %s)",
            [(DEMO_TENANT_ID, *u) for u in users],
        )
        records = [(str(i), "alice" if i <= 50 else "bob", f"confidential record {i}") for i in range(1, 101)]
        cur.executemany(
            "INSERT INTO records (tenant_id, id, owner_id, data) VALUES (%s, %s, %s, %s)",
            [(DEMO_TENANT_ID, *r) for r in records],
        )
        cur.executemany(
            "INSERT INTO assignments (tenant_id, subject_id, record_id) VALUES (%s, %s, %s)",
            [(DEMO_TENANT_ID, "dr_singh", str(i)) for i in range(1, 26)],
        )
        cur.executemany(
            "INSERT INTO assignments (tenant_id, subject_id, record_id) VALUES (%s, %s, %s)",
            [(DEMO_TENANT_ID, "dr_lee", str(i)) for i in range(26, 51)],
        )
        cur.execute(
            "INSERT INTO access_grants (tenant_id, subject_id, record_id, expires_at, reason, approved_by) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (DEMO_TENANT_ID, "support_amy", "17", time.time() + 3600, "ticket-8431", ADMIN_ROLE),
        )
        cur.executemany(
            "INSERT INTO access_grants (tenant_id, subject_id, record_id, expires_at, reason, approved_by) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            [
                (DEMO_TENANT_ID, "dr_cover", "8", time.time() + 1800, "shift-cover-ward-a", ADMIN_ROLE),
                (DEMO_TENANT_ID, "dr_cover", "31", time.time() + 1800, "shift-cover-ward-b", ADMIN_ROLE),
            ],
        )


def authorization_context(tenant_id: str, subject: str, record_id: int | str) -> dict:
    """Authoritative policy for the demo/dashboard's own record model.
    The learned graph is never an authorization source."""
    with db() as c:
        rec_id = str(record_id)
        DENY_EXPLANATION = "Access denied: you are not the owner, are not assigned, and have no active delegation."
        record = c.execute("SELECT owner_id FROM records WHERE tenant_id = %s AND id = %s",
                            (tenant_id, rec_id)).fetchone()
        if not record:
            return {"authorization": None, "explanations": [DENY_EXPLANATION], "delegation": None}
        if record["owner_id"] == subject:
            return {"authorization": "owner", "explanations": ["Access allowed: you own this record."], "delegation": None}
        if c.execute("SELECT 1 FROM assignments WHERE tenant_id = %s AND subject_id = %s AND record_id = %s",
                     (tenant_id, subject, rec_id)).fetchone():
            return {"authorization": "assigned", "explanations": ["Access allowed: you are assigned to this record."], "delegation": None}
        grant = c.execute(
            "SELECT expires_at, reason, approved_by FROM access_grants WHERE tenant_id = %s AND subject_id = %s AND record_id = %s",
            (tenant_id, subject, rec_id)).fetchone()
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


def record_audit(tenant_id: str, subject: str, record_id: int | str, authorization: str | None,
                  decision: str, outcome: str, explanations: list[str]) -> None:
    with db() as c:
        c.execute(
            'INSERT INTO audit_events (tenant_id, occurred_at, subject_id, record_id, "authorization", '
            "detector_decision, outcome, explanation) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (tenant_id, time.time(), subject, str(record_id), authorization, decision, outcome, " | ".join(explanations)),
        )


def compute_record_graph_features(tenant_id: str, record_id: int | str) -> dict:
    with db() as c:
        rows = c.execute(
            "SELECT subject, at, endpoint FROM risk_events WHERE tenant_id = %s AND record_id = %s ORDER BY at ASC",
            (tenant_id, str(record_id))).fetchall()
    if not rows:
        return {
            "inter_api_access_duration(sec)": 0.0, "api_access_uniqueness": 0.0,
            "sequence_length(count)": 0, "vsession_duration(min)": 0.0,
            "ip_type": "default", "num_sessions": 0, "num_users": 0,
            "num_unique_apis": 0, "source": "E",
        }
    subjects = [r["subject"] for r in rows]
    times = [r["at"] for r in rows]
    endpoints = {r["endpoint"] for r in rows}
    deltas = [b - a for a, b in zip(times, times[1:])]
    return {
        "inter_api_access_duration(sec)": (sum(deltas) / len(deltas)) if deltas else 0.0,
        "api_access_uniqueness": len(set(subjects)) / len(subjects),
        "sequence_length(count)": len(rows),
        "vsession_duration(min)": (times[-1] - times[0]) / 60.0,
        "ip_type": "default",
        "num_sessions": len(rows),
        "num_users": len(set(subjects)),
        "num_unique_apis": len(endpoints),
        "source": "E",
    }


def score_record_graph_anomaly(tenant_id: str, record_id: int | str) -> dict | None:
    if endpoint_anomaly_model is None:
        return None
    features = compute_record_graph_features(tenant_id, record_id)
    frame = pd.DataFrame([features])
    prediction = endpoint_anomaly_model.predict(frame)[0]
    probability = endpoint_anomaly_model.predict_proba(frame)[0][1]
    return {"is_anomalous": bool(prediction), "anomaly_probability": round(float(probability), 4)}


@dataclass
class Event:
    record_id: str
    allowed: bool
    at: float
    endpoint: str = "records"


class BehavioralRiskEngine:
    """Sliding-window behavioral detector. All mutable state (events, strikes,
    blocks, pending/approved bans) lives in Postgres, scoped by tenant_id -
    tenant A's traffic can never affect tenant B's risk scores or blocks."""

    def __init__(self, short_window: float = 30.0, long_window: float = 3600.0, block_duration: float = 120.0,
                 rapid_threshold: int = 4, slow_threshold: int = 15, strike_window: float = 86400.0):
        self.short_window = short_window
        self.long_window = long_window
        self.block_duration = block_duration
        self.rapid_threshold = rapid_threshold
        self.slow_threshold = slow_threshold
        self.strike_window = strike_window

    def record_event(self, tenant_id: str, subject: str, record_id: int | str, allowed: bool,
                      at: float | None = None, endpoint: str = "records") -> None:
        at = at if at is not None else time.time()
        with db() as c:
            c.execute(
                "INSERT INTO risk_events (tenant_id, subject, record_id, allowed, at, endpoint) VALUES (%s, %s, %s, %s, %s, %s)",
                (tenant_id, subject, str(record_id), allowed, at, endpoint))

    def _events(self, tenant_id: str, subject: str, now: float) -> list[Event]:
        cutoff = now - self.long_window
        with db() as c:
            rows = c.execute(
                "SELECT record_id, allowed, at, endpoint FROM risk_events "
                "WHERE tenant_id = %s AND subject = %s AND at > %s ORDER BY at ASC",
                (tenant_id, subject, cutoff)).fetchall()
        return [Event(r["record_id"], bool(r["allowed"]), r["at"], r["endpoint"]) for r in rows]

    def get_strike_count(self, tenant_id: str, subject: str, now: float | None = None) -> int:
        now = now or time.time()
        cutoff = now - self.strike_window
        with db() as c:
            c.execute("DELETE FROM risk_strikes WHERE tenant_id = %s AND subject = %s AND at <= %s",
                      (tenant_id, subject, cutoff))
            row = c.execute("SELECT COUNT(*) AS n FROM risk_strikes WHERE tenant_id = %s AND subject = %s AND at > %s",
                             (tenant_id, subject, cutoff)).fetchone()
        return row["n"]

    def _ban_status(self, tenant_id: str, subject: str) -> str | None:
        with db() as c:
            row = c.execute("SELECT status FROM risk_bans WHERE tenant_id = %s AND subject = %s",
                             (tenant_id, subject)).fetchone()
        return row["status"] if row else None

    def _set_ban_status(self, tenant_id: str, subject: str, status: str) -> None:
        with db() as c:
            c.execute(
                "INSERT INTO risk_bans (tenant_id, subject, status) VALUES (%s, %s, %s) "
                "ON CONFLICT (tenant_id, subject) DO UPDATE SET status = EXCLUDED.status",
                (tenant_id, subject, status))

    def _clear_ban_status(self, tenant_id: str, subject: str) -> None:
        with db() as c:
            c.execute("DELETE FROM risk_bans WHERE tenant_id = %s AND subject = %s", (tenant_id, subject))

    def _set_blocked_until(self, tenant_id: str, subject: str, until: float) -> None:
        with db() as c:
            c.execute(
                "INSERT INTO risk_blocks (tenant_id, subject, blocked_until) VALUES (%s, %s, %s) "
                "ON CONFLICT (tenant_id, subject) DO UPDATE SET blocked_until = EXCLUDED.blocked_until",
                (tenant_id, subject, until))

    def blocked_until(self, tenant_id: str, subject: str) -> float:
        with db() as c:
            row = c.execute("SELECT blocked_until FROM risk_blocks WHERE tenant_id = %s AND subject = %s",
                             (tenant_id, subject)).fetchone()
        return row["blocked_until"] if row else 0.0

    def register_strike_and_block(self, tenant_id: str, subject: str, now: float) -> tuple[float, str, int]:
        with db() as c:
            c.execute("INSERT INTO risk_strikes (tenant_id, subject, at) VALUES (%s, %s, %s)",
                      (tenant_id, subject, now))
        count = self.get_strike_count(tenant_id, subject, now)

        if count == 1:
            lockout, signal = 120.0, "strike_1_soft_lockout_2m"
        elif count == 2:
            lockout, signal = 1800.0, "strike_2_hard_lockout_30m"
        elif self._ban_status(tenant_id, subject) == "approved":
            lockout, signal = 315360000.0, "strike_3_permanent_ban_approved"
        else:
            self._set_ban_status(tenant_id, subject, "pending")
            lockout, signal = 1800.0, "strike_3_pending_admin_approval"

        self._set_blocked_until(tenant_id, subject, now + lockout)
        return lockout, signal, count

    def approve_permanent_ban(self, tenant_id: str, subject: str, now: float | None = None) -> bool:
        now = now or time.time()
        self._set_ban_status(tenant_id, subject, "approved")
        self._set_blocked_until(tenant_id, subject, now + 315360000.0)
        return True

    def reject_permanent_ban(self, tenant_id: str, subject: str, now: float | None = None) -> bool:
        now = now or time.time()
        self._clear_ban_status(tenant_id, subject)
        with db() as c:
            row = c.execute("SELECT ctid FROM risk_strikes WHERE tenant_id = %s AND subject = %s ORDER BY at DESC LIMIT 1",
                             (tenant_id, subject)).fetchone()
            if row:
                c.execute("DELETE FROM risk_strikes WHERE ctid = %s", (row["ctid"],))
        self._set_blocked_until(tenant_id, subject, now + 60.0)
        return True

    def pending_bans(self, tenant_id: str) -> list[str]:
        with db() as c:
            rows = c.execute("SELECT subject FROM risk_bans WHERE tenant_id = %s AND status = 'pending'",
                              (tenant_id,)).fetchall()
        return [r["subject"] for r in rows]

    def approved_bans(self, tenant_id: str) -> list[str]:
        with db() as c:
            rows = c.execute("SELECT subject FROM risk_bans WHERE tenant_id = %s AND status = 'approved'",
                              (tenant_id,)).fetchall()
        return [r["subject"] for r in rows]

    def cleanup_stale(self, tenant_id: str) -> None:
        now = time.time()
        cutoff = now - self.long_window
        strike_cutoff = now - self.strike_window
        with db() as c:
            c.execute("DELETE FROM risk_events WHERE tenant_id = %s AND at <= %s", (tenant_id, cutoff))
            c.execute("DELETE FROM risk_strikes WHERE tenant_id = %s AND at <= %s", (tenant_id, strike_cutoff))
            c.execute("DELETE FROM risk_blocks WHERE tenant_id = %s AND blocked_until < %s", (tenant_id, now))

    def reset(self, tenant_id: str) -> None:
        with db() as c:
            c.execute("DELETE FROM risk_events WHERE tenant_id = %s", (tenant_id,))
            c.execute("DELETE FROM risk_strikes WHERE tenant_id = %s", (tenant_id,))
            c.execute("DELETE FROM risk_blocks WHERE tenant_id = %s", (tenant_id,))
            c.execute("DELETE FROM risk_bans WHERE tenant_id = %s", (tenant_id,))

    def active_subject_count(self, tenant_id: str) -> int:
        now = time.time()
        with db() as c:
            row = c.execute("SELECT COUNT(DISTINCT subject) AS n FROM risk_events WHERE tenant_id = %s AND at > %s",
                             (tenant_id, now - self.long_window)).fetchone()
        return row["n"]

    def blocked_subject_count(self, tenant_id: str) -> int:
        now = time.time()
        with db() as c:
            row = c.execute("SELECT COUNT(*) AS n FROM risk_blocks WHERE tenant_id = %s AND blocked_until > %s",
                             (tenant_id, now)).fetchone()
        return row["n"]

    def coordinated_attacks(self, tenant_id: str, threshold: int = 50) -> dict:
        with db() as c:
            rows = c.execute(
                "SELECT record_id, COUNT(DISTINCT subject) AS n FROM risk_events "
                "WHERE tenant_id = %s AND allowed = false GROUP BY record_id HAVING COUNT(DISTINCT subject) >= %s",
                (tenant_id, threshold)).fetchall()
        return {r["record_id"]: r["n"] for r in rows}

    def evaluate(self, tenant_id: str, subject: str, record_id: int | str, allowed: bool,
                 endpoint: str = "records") -> tuple[str, list[str], bool, int, str]:
        now = time.time()

        if self.blocked_until(tenant_id, subject) > now:
            strike_count = self.get_strike_count(tenant_id, subject, now)
            status = self._ban_status(tenant_id, subject)
            if status == "approved":
                sig = "strike_3_permanent_ban_approved"
            elif status == "pending" or strike_count >= 3:
                sig = "strike_3_pending_admin_approval"
            elif strike_count == 2:
                sig = "strike_2_hard_lockout_30m"
            else:
                sig = "strike_1_soft_lockout_2m"
            return "block", ["temporarily_blocked", sig], False, 100, "Attack"

        self.record_event(tenant_id, subject, record_id, allowed, now, endpoint)

        score_data = self.compute_risk(tenant_id, subject, now)
        score, signals, category = score_data["score"], score_data["signals"], score_data["category"]

        unseen = False
        decision = "allow" if allowed else "deny"
        if score >= 90:
            decision = "block"
            lockout, strike_sig, count = self.register_strike_and_block(tenant_id, subject, now)
            signals.append("blocked_due_to_high_risk")
            signals.append(strike_sig)

        return decision, signals, unseen, score, category

    def compute_risk(self, tenant_id: str, subject: str, now: float) -> dict:
        q = self._events(tenant_id, subject, now)

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

        # Sequential short - best-effort: only numeric record_ids can show a "step"
        # pattern; arbitrary string resource_ids (e.g. from external /v1/authorize
        # tenants) simply never trip this signal, a documented limitation.
        short_ids_raw = [e.record_id for e in q if (not e.allowed) and (now - e.at <= self.short_window) and e.endpoint == "records"]
        short_ids = []
        for rid in short_ids_raw:
            try:
                short_ids.append(int(rid))
            except (TypeError, ValueError):
                pass
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

        if failed_long > 0:
            failure_ratio = failed_long / total_long if total_long > 0 else 0.0
            feature_vector = np.array([[unique_denied_short, sequential_steps, unique_denied_long,
                                         failure_ratio, endpoints_hit]])
            if anomaly_model.predict(feature_vector)[0] == -1:
                contributions["ml_behavioral_anomaly"] = 15
                signals.append("ml_behavioral_anomaly")

        score = min(100, sum(contributions.values()))

        if self.blocked_until(tenant_id, subject) > now:
            contributions["blocked_override"] = 100 - sum(contributions.values())
            score = 100
            if "temporarily_blocked" not in signals:
                signals.append("temporarily_blocked")
            strike_count = self.get_strike_count(tenant_id, subject, now)
            status = self._ban_status(tenant_id, subject)
            if status == "approved":
                if "strike_3_permanent_ban_approved" not in signals:
                    signals.append("strike_3_permanent_ban_approved")
            elif status == "pending" or strike_count >= 3:
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

_frontend_origins = [o.strip() for o in os.environ.get("FRONTEND_ORIGIN", "").split(",") if o.strip()]
_cors_origins = _frontend_origins if _frontend_origins else (["*"] if APP_ENV != "prod" else [])
app.add_middleware(CORSMiddleware, allow_origins=_cors_origins, allow_credentials=False, allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "env": APP_ENV, "demo_mode": DEMO_MODE}


def _rate_limit_key(request: Request) -> str:
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_exp": False})
            return f"subject:{payload.get('tenant_id', '?')}:{payload.get('sub', 'unknown')}"
        except jwt.InvalidTokenError:
            pass
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        return f"apikey:{hash_api_key(api_key)[:16]}"
    return get_remote_address(request)


limiter = Limiter(key_func=_rate_limit_key)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def create_access_token(subject: str, role: str, tenant_id: str) -> str:
    now = time.time()
    payload = {"sub": subject, "role": role, "tenant_id": tenant_id, "iat": now, "exp": now + JWT_EXPIRY_SECONDS}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_identity(authorization: str | None = Header(default=None)) -> tuple[str, str, str]:
    """Real authentication: a signed, time-bound JWT bearer token, verified
    server-side, scoped to a single tenant via the tenant_id claim."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Missing or malformed Authorization header (expected 'Bearer <token>')")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired, please log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid authentication token")
    return payload["sub"], payload.get("role", "customer"), payload.get("tenant_id", DEMO_TENANT_ID)


def get_tenant_from_api_key(x_api_key: str | None = Header(default=None)) -> str:
    """Product-API auth: a per-tenant API key (server-to-server), separate from
    the JWT user-login flow the demo dashboard uses."""
    if not x_api_key:
        raise HTTPException(401, "Missing X-API-Key header")
    with db() as c:
        row = c.execute("SELECT id FROM tenants WHERE api_key_hash = %s", (hash_api_key(x_api_key),)).fetchone()
    if not row:
        raise HTTPException(401, "Invalid API key")
    return row["id"]


def require_security_admin(role: str) -> None:
    if role != ADMIN_ROLE:
        raise HTTPException(403, f"This action requires the {ADMIN_ROLE} role")


def guard_demo_endpoint(authorization: str | None = Header(default=None)) -> None:
    if DEMO_MODE:
        return
    subject, role, _tenant_id = get_current_identity(authorization)
    require_security_admin(role)


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
        "strike_3_permanent_ban_approved": "Strike 3/3: Permanent Firewall Blacklist APPROVED by Administrator.",
        "ml_behavioral_anomaly": "An unsupervised ML model (Isolation Forest) flagged this access pattern as statistically abnormal compared to normal traffic."
    }
    return [messages[s] for s in signals if s in messages]


@app.post("/auth/register")
@limiter.limit("100/minute")
def register(request: Request, payload: dict) -> dict:
    subject = payload.get("subject")
    password = payload.get("password")
    role = payload.get("role", "customer")
    if not subject or not password:
        raise HTTPException(400, "subject and password are required")
    if role == ADMIN_ROLE:
        raise HTTPException(400, f"Cannot self-register with the {ADMIN_ROLE} role")
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    with db() as c:
        if c.execute("SELECT 1 FROM users WHERE tenant_id = %s AND id = %s", (DEMO_TENANT_ID, subject)).fetchone():
            raise HTTPException(409, "Subject already registered")
        c.execute("INSERT INTO users (tenant_id, id, role, password_hash) VALUES (%s, %s, %s, %s)",
                  (DEMO_TENANT_ID, subject, role, password_hash))
    return {"status": "registered", "subject": subject, "role": role}


@app.post("/auth/login")
@limiter.limit("1000/minute")
def login(request: Request, payload: dict) -> dict:
    subject = payload.get("subject")
    password = payload.get("password")
    if not subject or not password:
        raise HTTPException(400, "subject and password are required")
    with db() as c:
        row = c.execute("SELECT role, password_hash FROM users WHERE tenant_id = %s AND id = %s",
                         (DEMO_TENANT_ID, subject)).fetchone()
    if not row or not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        raise HTTPException(401, "Invalid subject or password")
    token = create_access_token(subject, row["role"], DEMO_TENANT_ID)
    return {"access_token": token, "token_type": "bearer", "subject": subject, "role": row["role"], "expires_in": JWT_EXPIRY_SECONDS}


@app.get("/auth/me")
def me(identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    subject, role, tenant_id = identity
    return {"subject": subject, "role": role, "tenant_id": tenant_id}


@app.post("/reset")
@limiter.limit("60/minute")
def reset(request: Request, _guard: None = Depends(guard_demo_endpoint)) -> dict:
    seed_demo_tenant(force=True)
    engine.reset(DEMO_TENANT_ID)
    return {"status": "reset"}


soc_alerts: list[dict] = []


def dispatch_soc_alert(tenant_id: str, subject: str, record_id: int | str, score: int, category: str, signals: list[str]) -> dict:
    strikes = max(1, engine.get_strike_count(tenant_id, subject))
    tier = "PERMANENT_BLACKLIST" if strikes >= 3 else ("HARD_LOCKOUT_30M" if strikes == 2 else "SOFT_LOCKOUT_2M")
    mitigation = "PERMANENT_IDENTITY_BLACKLIST (Strike 3/3)" if strikes >= 3 else ("AUTOMATIC_IDENTITY_LOCKOUT_30M (Strike 2/3)" if strikes == 2 else "AUTOMATIC_IDENTITY_LOCKOUT_120S (Strike 1/3)")

    alert_payload = {
        "alert_id": f"SOC-ALERT-{int(time.time() * 1000)}",
        "tenant_id": tenant_id,
        "timestamp": time.time(),
        "severity": "CRITICAL" if (score >= 90 or strikes >= 2) else "HIGH",
        "threat_type": "BOLA_ENUMERATION_ATTACK",
        "attacker_identity": subject,
        "targeted_record_id": str(record_id),
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


@app.get("/healthz")
def healthz() -> dict:
    try:
        with db() as c:
            c.execute("SELECT 1").fetchone()
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    return {"status": "ok" if db_status == "connected" else "degraded", "db": db_status, "env": APP_ENV}


@app.get("/records/{record_id}")
@limiter.limit("1000/minute")
def get_record(record_id: str, request: Request, response: Response,
               identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    subject, _role, tenant_id = identity

    access = authorization_context(tenant_id, subject, record_id)
    authorization = access["authorization"]

    decision, signals, unseen, score, category = engine.evaluate(tenant_id, subject, record_id, authorization is not None)
    detector_explanations = explain_detector_signals(signals)
    explanations = access["explanations"] + detector_explanations

    response.headers["X-Detector-Decision"] = decision
    response.headers["X-Detector-Signals"] = ",".join(signals)
    response.headers["X-Graph-Unseen"] = str(unseen).lower()
    response.headers["X-Risk-Score"] = str(score)
    response.headers["X-Risk-Category"] = category

    if decision == "block":
        explanations = ["Access blocked: BOLA-style behavior was detected."] + explanations
        record_audit(tenant_id, subject, record_id, authorization, decision, "blocked", explanations)
        dispatch_soc_alert(tenant_id, subject, record_id, score, category, signals)
        raise HTTPException(403, detail={"outcome": "blocked", "reason": "BOLA-style behavior detected", "signals": signals,
                                         "explanations": explanations, "score": score, "category": category,
                                         "soc_alert_dispatched": True},
                            headers={"X-Detector-Decision": decision, "X-Detector-Signals": ",".join(signals),
                                     "X-Graph-Unseen": str(unseen).lower(), "X-Risk-Score": str(score), "X-Risk-Category": category})
    if authorization is None:
        record_audit(tenant_id, subject, record_id, authorization, decision, "denied", explanations)
        raise HTTPException(403, detail={"outcome": "denied", "reason": "No valid object-level authorization", "explanations": explanations, "score": score, "category": category},
                            headers={"X-Detector-Decision": decision, "X-Detector-Signals": ",".join(signals),
                                     "X-Graph-Unseen": str(unseen).lower(), "X-Risk-Score": str(score), "X-Risk-Category": category})
    with db() as c:
        row = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                         (tenant_id, str(record_id))).fetchone()
    record_audit(tenant_id, subject, record_id, authorization, decision, "allowed", explanations)
    return {"record": dict(row), "authorization": authorization, "graph_edge_known": not unseen,
            "delegation": access["delegation"], "decision": {"outcome": "allowed", "explanations": explanations},
            "score": score, "category": category}


@app.get("/audit-events")
def get_audit_events(identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    _subject, role, tenant_id = identity
    require_security_admin(role)
    with db() as c:
        rows = c.execute(
            'SELECT id, occurred_at, subject_id, record_id, "authorization", detector_decision, outcome, explanation '
            "FROM audit_events WHERE tenant_id = %s ORDER BY id DESC LIMIT 100", (tenant_id,)).fetchall()
    return {"events": [dict(row) for row in rows]}


def _login_headers(client, subject: str, password: str = DEMO_PASSWORD) -> dict:
    res = client.post("/auth/login", json={"subject": subject, "password": password})
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@app.post("/simulate/normal")
@limiter.limit("5/minute")
def simulate_normal(request: Request, _guard: None = Depends(guard_demo_endpoint)) -> dict:
    from fastapi.testclient import TestClient
    client = TestClient(app)
    headers = _login_headers(client, "alice")
    results = []
    for i in range(1, 51):
        res = client.get(f"/records/{i}", headers=headers)
        results.append(res.status_code)
    return {"status": "normal_simulated", "requests": 50, "results": results}

@app.post("/simulate/rapid")
@limiter.limit("5/minute")
def simulate_rapid(request: Request, _guard: None = Depends(guard_demo_endpoint)) -> dict:
    from fastapi.testclient import TestClient
    client = TestClient(app)
    headers = _login_headers(client, "attacker_1")
    results = []
    for i in range(51, 56):
        res = client.get(f"/records/{i}", headers=headers)
        results.append({"id": i, "status": res.status_code, "risk": res.headers.get("X-Risk-Score"), "category": res.headers.get("X-Risk-Category")})
    return {"status": "rapid_simulated", "results": results}

@app.post("/simulate/low_and_slow")
@limiter.limit("5/minute")
def simulate_low_and_slow(request: Request, _guard: None = Depends(guard_demo_endpoint)) -> dict:
    from fastapi.testclient import TestClient
    client = TestClient(app)
    results = []

    subject = "attacker_slow"
    now = time.time()

    for i in range(15):
        event_time = now - (3600) + (i * 240)
        engine.record_event(DEMO_TENANT_ID, subject, 50 + i, False, event_time)
        record_audit(DEMO_TENANT_ID, subject, 50 + i, None, "deny", "denied", ["Simulated low and slow deny"])

    headers = _login_headers(client, subject)
    res = client.get("/records/66", headers=headers)
    results.append({"status": res.status_code, "risk": res.headers.get("X-Risk-Score"), "category": res.headers.get("X-Risk-Category")})
    return {"status": "low_and_slow_simulated", "results": results}

@app.post("/simulate/coordinated")
@limiter.limit("5/minute")
def simulate_coordinated(request: Request, _guard: None = Depends(guard_demo_endpoint)) -> dict:
    from fastapi.testclient import TestClient
    client = TestClient(app)
    for i in range(1, 51):
        headers = _login_headers(client, f"sybil_{i}")
        client.get("/records/1", headers=headers)
    return {"status": "coordinated_simulated"}


@app.get("/users/{user_id}")
def get_user(user_id: str, response: Response, identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    subject, _role, tenant_id = identity
    decision, signals, unseen, score, category = engine.evaluate(tenant_id, subject, user_id, False, endpoint="users")
    if decision == "block":
        raise HTTPException(403, detail={"outcome": "blocked", "score": score, "category": category})
    raise HTTPException(403, detail={"outcome": "denied", "score": score, "category": category})

@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: str, response: Response, identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    subject, _role, tenant_id = identity
    decision, signals, unseen, score, category = engine.evaluate(tenant_id, subject, invoice_id, False, endpoint="invoices")
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
        "strike_3_duration": "Permanent (Blacklist)",
        "ai_anomaly_detection": "IsolationForest (scikit-learn)",
        "auth": "JWT bearer tokens (HS256) for the dashboard; per-tenant API keys for /v1/*",
        "state_backend": "Postgres (multi-tenant, tenant_id-scoped)"
    }

@app.get("/stats")
def get_stats() -> dict:
    engine.cleanup_stale(DEMO_TENANT_ID)
    return {"active_subjects": engine.active_subject_count(DEMO_TENANT_ID),
            "blocked_subjects": engine.blocked_subject_count(DEMO_TENANT_ID),
            "coordinated_attacks": engine.coordinated_attacks(DEMO_TENANT_ID)}

@app.get("/events")
def get_events(identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    _subject, role, tenant_id = identity
    require_security_admin(role)
    with db() as c:
        rows = c.execute(
            'SELECT id, occurred_at, subject_id, record_id, "authorization", detector_decision, outcome, explanation '
            "FROM audit_events WHERE tenant_id = %s ORDER BY id DESC LIMIT 50", (tenant_id,)).fetchall()
    return {"events": [dict(row) for row in rows]}

@app.get("/risk/{subject}")
def get_risk(subject: str) -> dict:
    now = time.time()
    tenant_id = DEMO_TENANT_ID
    res = engine.compute_risk(tenant_id, subject, now)
    strikes = engine.get_strike_count(tenant_id, subject, now)
    blocked_until = engine.blocked_until(tenant_id, subject)
    is_blocked = blocked_until > now
    remaining = int(blocked_until - now) if is_blocked else 0
    status = engine._ban_status(tenant_id, subject)
    is_pending = status == "pending" or (strikes >= 3 and status != "approved" and is_blocked)
    is_approved = status == "approved" or (is_blocked and remaining > 86400 * 30)
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
def approve_permanent_ban_endpoint(subject: str, identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    caller, role, tenant_id = identity
    require_security_admin(role)
    engine.approve_permanent_ban(tenant_id, subject)
    record_audit(tenant_id, subject, 0, "ADMIN_AUTHORITY", "block", "blocked", [f"Admin '{caller}' APPROVED Permanent Firewall Ban for '{subject}'"])
    return {"status": "permanent_ban_approved", "subject": subject, "is_permanent": True}


@app.post("/admin/reject-ban/{subject}")
def reject_permanent_ban_endpoint(subject: str, identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    caller, role, tenant_id = identity
    require_security_admin(role)
    engine.reject_permanent_ban(tenant_id, subject)
    record_audit(tenant_id, subject, 0, "ADMIN_AUTHORITY", "allow", "allowed", [f"Admin '{caller}' DISMISSED Permanent Ban for '{subject}' (Quarantine Relaxed)"])
    return {"status": "ban_dismissed", "subject": subject, "is_permanent": False}


@app.get("/admin/pending-bans")
def get_pending_bans(identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    _subject, role, tenant_id = identity
    require_security_admin(role)
    return {"pending_bans": engine.pending_bans(tenant_id), "approved_bans": engine.approved_bans(tenant_id)}


@app.get("/soc/alerts")
def get_soc_alerts(identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    _subject, role, tenant_id = identity
    require_security_admin(role)
    tenant_alerts = [a for a in soc_alerts if a.get("tenant_id") == tenant_id]
    return {"total_alerts": len(tenant_alerts), "recent_alerts": tenant_alerts[:20]}


@app.post("/soc/test-webhook")
def test_soc_webhook(payload: dict | None = None, identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    _subject, role, tenant_id = identity
    require_security_admin(role)
    if not payload:
        payload = dispatch_soc_alert(
            tenant_id, subject="simulated_adversary", record_id=999, score=100, category="Attack",
            signals=["unauthorized_unique_object_pressure", "sequential_id_enumeration", "manual_test"]
        )
    else:
        subject = payload.get("attacker_identity", "external_attacker")
        target_id = payload.get("targeted_object_id", 0)
        signals = payload.get("signals_tripped", ["bola_attempt"])
        decision = payload.get("decision", "deny")
        outcome = "blocked" if decision == "block" else "denied"
        explanation = f"External BOLA Activity: {','.join(signals)}" if outcome == "blocked" else f"External Object Denied: Attempted {target_id}"

        engine.record_event(tenant_id, subject, target_id, False, time.time(), "records")
        if decision == "block":
            lockout, strike_sig, count = engine.register_strike_and_block(tenant_id, subject, time.time())
            if strike_sig not in signals:
                signals.append(strike_sig)
            score = payload.get("risk_score", 100)
            category = payload.get("risk_category", "Attack")
            dispatch_soc_alert(tenant_id, subject, target_id, score, category, signals)

        record_audit(tenant_id, subject, target_id, None, decision, outcome, [explanation])
    return {"status": "alert_logged_and_synced", "payload": payload}


@app.get("/records/{record_id}/graph-risk")
def get_record_graph_risk(record_id: str, identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    _subject, _role, tenant_id = identity
    result = score_record_graph_anomaly(tenant_id, record_id)
    if result is None:
        raise HTTPException(503, "Endpoint anomaly model not trained yet - run train_endpoint_anomaly_model.py")
    return {"record_id": record_id, **result, "features": compute_record_graph_features(tenant_id, record_id)}


# --- Product API: what other companies' backends actually integrate against ---
# Server-to-server, authenticated by a per-tenant API key (not the demo's JWT
# login flow). The caller already knows whether the requesting subject is
# authorized for the resource (their own object model, not ours) - this
# endpoint's job is purely the behavioral/risk layer on top of that decision.

@app.post("/v1/tenants")
@limiter.limit("10/minute")
def create_tenant(request: Request, payload: dict, x_signup_key: str | None = Header(default=None)) -> dict:
    if x_signup_key != TENANT_SIGNUP_KEY:
        raise HTTPException(403, "Invalid signup key")
    name = payload.get("name")
    if not name:
        raise HTTPException(400, "name is required")
    tenant_id = secrets.token_hex(8)
    api_key = generate_api_key()
    with db() as c:
        c.execute("INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (%s, %s, %s, %s)",
                  (tenant_id, name, hash_api_key(api_key), time.time()))
    return {
        "tenant_id": tenant_id,
        "name": name,
        "api_key": api_key,
        "warning": "This API key is shown once and cannot be retrieved again - store it securely.",
    }


@app.post("/v1/authorize")
@limiter.limit("1000/minute")
def v1_authorize(request: Request, payload: dict, tenant_id: str = Depends(get_tenant_from_api_key)) -> dict:
    subject = payload.get("subject")
    resource_id = payload.get("resource_id")
    authorized = bool(payload.get("authorized", False))
    if not subject or resource_id is None:
        raise HTTPException(400, "subject and resource_id are required")

    decision, signals, _unseen, score, category = engine.evaluate(tenant_id, subject, resource_id, authorized, endpoint="v1")
    detector_explanations = explain_detector_signals(signals)

    outcome = "blocked" if decision == "block" else ("allowed" if authorized else "denied")
    record_audit(tenant_id, subject, resource_id, "authorized" if authorized else None, decision, outcome, detector_explanations)
    if decision == "block":
        dispatch_soc_alert(tenant_id, subject, resource_id, score, category, signals)

    final_decision = "block" if decision == "block" else ("allow" if authorized else "deny")
    return {
        "decision": final_decision,
        "score": score,
        "category": category,
        "signals": signals,
        "explanations": detector_explanations,
    }


def ensure_database() -> None:
    init_schema()
    seed_demo_tenant(force=False)


ensure_database()
