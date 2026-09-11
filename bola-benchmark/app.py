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
import hmac
import json
import os
import re
import secrets
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

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
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import strawberry
from strawberry.fastapi import GraphQLRouter

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

# --- Dynamic BOLA Weights & Limits (Configurable, no hardcoded magic values) ---
BOLA_WEIGHT_DELETE = float(os.environ.get("BOLA_WEIGHT_DELETE", "3.0"))
BOLA_WEIGHT_PATCH = float(os.environ.get("BOLA_WEIGHT_PATCH", "2.5"))
BOLA_WEIGHT_PUT = float(os.environ.get("BOLA_WEIGHT_PUT", "2.0"))
BOLA_WEIGHT_POST = float(os.environ.get("BOLA_WEIGHT_POST", "1.5"))
BOLA_WEIGHT_GET = float(os.environ.get("BOLA_WEIGHT_GET", "1.0"))
BOLA_MAX_BATCH_SIZE = int(os.environ.get("BOLA_MAX_BATCH_SIZE", "50"))
BOLA_ASYNC_JOB_TTL = float(os.environ.get("BOLA_ASYNC_JOB_TTL", "3600.0"))

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL and APP_ENV == "prod":
    raise RuntimeError(
        "DATABASE_URL is required (Postgres connection string) in production - this app runs on "
        "Postgres in prod. For local dev/testing, SQLite fallback is enabled automatically."
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


if DATABASE_URL and not DATABASE_URL.startswith("sqlite"):
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
else:
    import sqlite3
    import re
    from threading import RLock

    _db_lock = RLock()
    _sqlite_file = Path(__file__).parent / "dev.db" if not (DATABASE_URL and ":memory:" in DATABASE_URL) else ":memory:"
    _raw_sqlite = sqlite3.connect(str(_sqlite_file), check_same_thread=False)
    _raw_sqlite.row_factory = sqlite3.Row

    class SQLiteCursorWrapper:
        def __init__(self, cur):
            self.cur = cur

        def _transform_sql(self, sql: str) -> str:
            s = sql.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
            s = s.replace("DOUBLE PRECISION", "REAL")
            s = s.replace("BOOLEAN", "INTEGER")
            s = re.sub(r'\ballowed\s*=\s*false\b', 'allowed = 0', s, flags=re.IGNORECASE)
            s = re.sub(r'\ballowed\s*=\s*true\b', 'allowed = 1', s, flags=re.IGNORECASE)
            s = re.sub(r'\bctid\b', 'rowid', s)
            s = re.sub(r'%s', '?', s)
            return s

        def execute(self, sql, params=None):
            s = self._transform_sql(sql)
            if params is not None:
                p = [int(x) if isinstance(x, bool) else x for x in params]
                self.cur.execute(s, p)
            else:
                stmts = [stmt.strip() for stmt in s.split(";") if stmt.strip()]
                if len(stmts) > 1:
                    self.cur.executescript(s)
                else:
                    self.cur.execute(s)
            return self

        def executemany(self, sql, seq_of_params):
            s = self._transform_sql(sql)
            p_seq = [[int(x) if isinstance(x, bool) else x for x in params] for params in seq_of_params]
            self.cur.executemany(s, p_seq)
            return self

        def fetchone(self):
            r = self.cur.fetchone()
            return dict(r) if r is not None else None

        def fetchall(self):
            return [dict(r) for r in self.cur.fetchall()]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class SQLiteConnWrapper:
        def __init__(self, conn):
            self.conn = conn

        def cursor(self):
            return SQLiteCursorWrapper(self.conn.cursor())

        def execute(self, sql, params=None):
            cur = self.cursor()
            cur.execute(sql, params)
            return cur

        def commit(self):
            self.conn.commit()

        def rollback(self):
            self.conn.rollback()

    _sqlite_wrapper = SQLiteConnWrapper(_raw_sqlite)

    @contextmanager
    def db():
        with _db_lock:
            try:
                yield _sqlite_wrapper
                _sqlite_wrapper.commit()
            except Exception:
                _sqlite_wrapper.rollback()
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
                endpoint TEXT NOT NULL,
                http_verb TEXT NOT NULL DEFAULT 'GET'
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
            CREATE TABLE IF NOT EXISTS resource_nodes (
                tenant_id TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                parent_type TEXT,
                parent_id TEXT,
                owner_id TEXT NOT NULL,
                name TEXT,
                metadata TEXT,
                PRIMARY KEY (tenant_id, resource_type, resource_id)
            );
            CREATE TABLE IF NOT EXISTS async_jobs (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                action TEXT NOT NULL,
                pre_authorized BOOLEAN NOT NULL DEFAULT FALSE,
                pre_auth_token TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at DOUBLE PRECISION NOT NULL,
                expires_at DOUBLE PRECISION NOT NULL,
                completed_at DOUBLE PRECISION,
                result_payload TEXT
            );
            CREATE TABLE IF NOT EXISTS stored_references (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                ref_type TEXT NOT NULL,
                target_resource_id TEXT NOT NULL,
                metadata TEXT,
                authorized_at_creation BOOLEAN NOT NULL,
                created_at DOUBLE PRECISION NOT NULL,
                last_validated_at DOUBLE PRECISION,
                status TEXT NOT NULL DEFAULT 'active'
            );
            CREATE TABLE IF NOT EXISTS abac_policies (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                effect TEXT NOT NULL,
                target_role TEXT,
                target_classification TEXT,
                min_clearance INTEGER DEFAULT 0,
                allowed_hours_start INTEGER DEFAULT 0,
                allowed_hours_end INTEGER DEFAULT 24,
                created_at DOUBLE PRECISION NOT NULL
            );
            CREATE TABLE IF NOT EXISTS abac_field_redactions (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                field_name TEXT NOT NULL,
                required_role TEXT,
                min_clearance INTEGER DEFAULT 0,
                masking_strategy TEXT NOT NULL DEFAULT 'REDACT'
            );
            CREATE TABLE IF NOT EXISTS canary_records (
                tenant_id TEXT NOT NULL,
                id TEXT NOT NULL,
                decoy_name TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'CRITICAL',
                trap_action TEXT NOT NULL DEFAULT 'PERMANENT_BAN',
                created_at DOUBLE PRECISION NOT NULL,
                PRIMARY KEY (tenant_id, id)
            );
            CREATE TABLE IF NOT EXISTS canary_triggers (
                id SERIAL PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                canary_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                ip_address TEXT,
                triggered_at DOUBLE PRECISION NOT NULL,
                action_taken TEXT NOT NULL
            );
            """
        )
        try:
            c.execute("ALTER TABLE risk_events ADD COLUMN http_verb TEXT NOT NULL DEFAULT 'GET'")
        except Exception:
            pass
        try:
            c.execute("ALTER TABLE records ADD COLUMN classification TEXT DEFAULT 'standard'")
        except Exception:
            pass


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
                       "risk_events", "risk_strikes", "risk_blocks", "risk_bans",
                       "resource_nodes", "async_jobs", "stored_references",
                       "abac_policies", "abac_field_redactions", "canary_records", "canary_triggers"):
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
        canaries = [
            ("0", "Demo Zero Honeypot", "CRITICAL", "PERMANENT_BAN", time.time()),
            ("999999", "High ID Probing Trap", "CRITICAL", "PERMANENT_BAN", time.time()),
            ("canary_admin_vault", "Admin Vault Decoy", "CRITICAL", "PERMANENT_BAN", time.time()),
        ]
        cur.executemany(
            "INSERT INTO canary_records (tenant_id, id, decoy_name, severity, trap_action, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (tenant_id, id) DO NOTHING",
            [(DEMO_TENANT_ID, *can) for can in canaries],
        )
        nodes = [
            ("organization", "org_demo", None, None, "alice", "Acme Health Corp", "{}"),
            ("department", "dept_cardiology", "organization", "org_demo", "dr_singh", "Cardiology Dept", "{}"),
            ("record", "1", "department", "dept_cardiology", "alice", "Patient 1 Vitals", "{}"),
            ("organization", "org_rival", None, None, "bob", "Rival Health Corp", "{}"),
            ("department", "dept_rival_oncology", "organization", "org_rival", "bob", "Oncology Dept", "{}"),
            ("record", "55", "department", "dept_rival_oncology", "bob", "Patient 55 Chart", "{}"),
        ]
        cur.executemany(
            "INSERT INTO resource_nodes (tenant_id, resource_type, resource_id, parent_type, parent_id, owner_id, name, metadata) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (tenant_id, resource_type, resource_id) DO NOTHING",
            [(DEMO_TENANT_ID, *n) for n in nodes],
        )
        redactions = [
            ("redact_psych", "record", "psychiatric_notes", "psychiatrist", 2, "REDACT"),
            ("redact_ssn", "record", "ssn", "billing_admin", 3, "REDACT"),
        ]
        cur.executemany(
            "INSERT INTO abac_field_redactions (id, tenant_id, resource_type, field_name, required_role, min_clearance, masking_strategy) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
            [(r[0], DEMO_TENANT_ID, *r[1:]) for r in redactions],
        )



def is_canary_record(tenant_id: str, record_id: str) -> bool:
    """Checks if record_id is a registered honeypot decoy in canary_records table."""
    with db() as c:
        row = c.execute("SELECT 1 FROM canary_records WHERE tenant_id = %s AND id = %s",
                         (tenant_id, str(record_id))).fetchone()
    return bool(row)


def trigger_canary_trap(tenant_id: str, subject: str, record_id: str, endpoint: str = "records", ip: str = "unknown") -> None:
    """Executes immediate permanent ban, immutable forensic trigger logging, and CRITICAL SOC alert on canary access."""
    now = time.time()
    with db() as c:
        c.execute(
            "INSERT INTO canary_triggers (tenant_id, canary_id, subject_id, endpoint, ip_address, triggered_at, action_taken) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (tenant_id, str(record_id), subject, endpoint, ip, now, "PERMANENT_BAN")
        )
    # Instant Strike 3 permanent ban: skip progressive warning windows
    engine._set_ban_status(tenant_id, subject, "approved")
    engine._set_blocked_until(tenant_id, subject, now + 315360000.0)  # 10 years
    with db() as c:
        # Record 3 strikes for forensics
        for offset in (0.0, 0.001, 0.002):
            c.execute("INSERT INTO risk_strikes (tenant_id, subject, at) VALUES (%s, %s, %s)",
                      (tenant_id, subject, now + offset))
    # Dispatch CRITICAL SOC alert
    dispatch_soc_alert(tenant_id, subject, record_id, score=100, category="Attack",
                       signals=["canary_honeypot_triggered", "strike_3_permanent_ban_approved"])
    record_audit(
        tenant_id, subject, record_id, None, "block", "blocked_canary",
        [f"CANARY HONEYPOT TRIGGERED: Decoy '{record_id}' accessed by subject '{subject}'. Permanent firewall ban enforced."]
    )


def authorization_context(tenant_id: str, subject: str, record_id: int | str, action: str = "read") -> dict:
    """Authoritative policy for the demo/dashboard's own record model.
    The learned graph is never an authorization source.
    Dynamically enforces read, write, patch, and delete permissions."""
    rec_id = str(record_id)
    # Honeypot decoy check (Feature 9)
    if is_canary_record(tenant_id, rec_id):
        trigger_canary_trap(tenant_id, subject, rec_id, endpoint="records")
        return {"authorization": None, "explanations": ["Access denied: you are not authorized to access this record."], "delegation": None, "is_canary": True}

    with db() as c:
        DENY_EXPLANATION = "Access denied: you are not the owner, are not assigned, and have no active delegation."
        record = c.execute("SELECT owner_id FROM records WHERE tenant_id = %s AND id = %s",
                            (tenant_id, rec_id)).fetchone()
        if not record:
            return {"authorization": None, "explanations": [DENY_EXPLANATION], "delegation": None}

        # Admin override (security_admin role has read/audit oversight)
        user_row = c.execute("SELECT role FROM users WHERE tenant_id = %s AND id = %s", (tenant_id, subject)).fetchone()
        user_role = user_row["role"] if user_row else None
        if user_role == ADMIN_ROLE or subject == ADMIN_ROLE:
            return {"authorization": "admin", "explanations": ["Access allowed: security_admin administrative authority."], "delegation": None}

        # Owner check (owner has all permissions: read, write, delete)
        if record["owner_id"] == subject:
            verb_note = "delete" if action == "delete" else ("modify" if action in ("write", "update", "patch") else "read")
            return {"authorization": "owner", "explanations": [f"Access allowed: you own this record and can {verb_note} it."], "delegation": None}

        # DELETE is strictly owner-only
        if action == "delete":
            return {"authorization": None, "explanations": ["Access denied: only the record owner can delete this record."], "delegation": None}

        # WRITE / PATCH: check if subject has explicit write assignment or delegation
        if action in ("write", "update", "patch"):
            return {"authorization": None, "explanations": ["Access denied: only the record owner can modify this record."], "delegation": None}

        # READ: check assignments
        if c.execute("SELECT 1 FROM assignments WHERE tenant_id = %s AND subject_id = %s AND record_id = %s",
                     (tenant_id, subject, rec_id)).fetchone():
            return {"authorization": "assigned", "explanations": ["Access allowed: you are assigned to this record."], "delegation": None}

        # READ: check active delegation
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
    http_verb: str = "GET"


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
                      at: float | None = None, endpoint: str = "records", http_verb: str = "GET") -> None:
        at = at if at is not None else time.time()
        with db() as c:
            c.execute(
                "INSERT INTO risk_events (tenant_id, subject, record_id, allowed, at, endpoint, http_verb) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (tenant_id, subject, str(record_id), allowed, at, endpoint, http_verb))

    def _events(self, tenant_id: str, subject: str, now: float) -> list[Event]:
        cutoff = now - self.long_window
        with db() as c:
            rows = c.execute(
                "SELECT record_id, allowed, at, endpoint, http_verb FROM risk_events "
                "WHERE tenant_id = %s AND subject = %s AND at > %s ORDER BY at ASC",
                (tenant_id, subject, cutoff)).fetchall()
        return [Event(r["record_id"], bool(r["allowed"]), r["at"], r["endpoint"], r.get("http_verb", "GET") or "GET") for r in rows]

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
                 endpoint: str = "records", http_verb: str = "GET") -> tuple[str, list[str], bool, int, str]:
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

        self.record_event(tenant_id, subject, record_id, allowed, now, endpoint, http_verb)

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

        def _is_tracked_resource(ep: str) -> bool:
            return ep in ("records", "v1", "records_batch", "records_mutation", "records_abac",
                          "graphql", "hierarchy", "exports", "stored_ref", "async_jobs") or ep.startswith("body_ref:")

        unique_denied_short = len({e.record_id for e in denied_short if _is_tracked_resource(e.endpoint)})
        unique_denied_long = len({e.record_id for e in denied_all if _is_tracked_resource(e.endpoint)})

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
        short_ids_raw = [e.record_id for e in q if (not e.allowed) and (now - e.at <= self.short_window) and _is_tracked_resource(e.endpoint)]
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

        # Feature 1: Write/Mutation weighted scoring
        denied_write_events = [e for e in denied_short if e.http_verb in ("DELETE", "PATCH", "PUT")]
        if denied_write_events:
            if any(e.http_verb == "DELETE" for e in denied_write_events):
                contributions["unauthorized_write_delete_attempt"] = int(25 * BOLA_WEIGHT_DELETE)
                signals.append("unauthorized_write_delete_attempt")
            elif any(e.http_verb in ("PATCH", "PUT") for e in denied_write_events):
                weight = max(BOLA_WEIGHT_PATCH if e.http_verb == "PATCH" else BOLA_WEIGHT_PUT for e in denied_write_events)
                contributions["unauthorized_write_mutation_attempt"] = int(20 * weight)
                signals.append("unauthorized_write_mutation_attempt")

        # Feature 2: Hierarchical chain mismatch
        if any(e.endpoint == "hierarchy" for e in denied_short):
            contributions["relational_chain_mismatch"] = 45
            signals.append("relational_chain_mismatch")

        # Feature 3: Body-payload object injection
        body_injections = [e for e in denied_short if e.endpoint.startswith("body_ref:")]
        if body_injections:
            contributions["body_payload_object_injection"] = min(40, len(body_injections) * 20)
            signals.append("body_payload_object_injection")

        # Feature 7: Second-order stored BOLA violation
        if any(e.endpoint.startswith("stored_ref") for e in denied_short):
            contributions["second_order_bola_violation"] = 45
            signals.append("second_order_bola_violation")

        # Feature 9: Canary honeypot trigger
        if any(e.endpoint == "canary_trap" for e in denied_short):
            contributions["canary_honeypot_triggered"] = 100
            signals.append("canary_honeypot_triggered")

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
app = FastAPI(title="BOLA Graph Benchmark", version="1.1.1")

_frontend_origins = [o.strip() for o in os.environ.get("FRONTEND_ORIGIN", "").split(",") if o.strip()]
_cors_origins = _frontend_origins if _frontend_origins else (["*"] if APP_ENV != "prod" else [])
app.add_middleware(CORSMiddleware, allow_origins=_cors_origins, allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

ID_KEY_PATTERN = re.compile(r'(?:^|[_\-.])(?:id|key|ref|uuid|identifier)s?$', re.IGNORECASE)

def extract_candidate_object_ids(payload: Any, depth: int = 5) -> list[tuple[str, str]]:
    """Recursively scans JSON payloads for object ID fields without hardcoding field names."""
    candidates = []
    if depth <= 0:
        return candidates
    if isinstance(payload, dict):
        for k, v in payload.items():
            if isinstance(v, (str, int)) and ID_KEY_PATTERN.search(str(k)):
                val_str = str(v).strip()
                if val_str and len(val_str) < 128:
                    candidates.append((str(k), val_str))
            elif isinstance(v, list) and ID_KEY_PATTERN.search(str(k)):
                for item in v:
                    if isinstance(item, (str, int)):
                        val_str = str(item).strip()
                        if val_str and len(val_str) < 128:
                            candidates.append((str(k), val_str))
            elif isinstance(v, (dict, list)):
                candidates.extend(extract_candidate_object_ids(v, depth - 1))
    elif isinstance(payload, list):
        for item in payload:
            if isinstance(item, (dict, list)):
                candidates.extend(extract_candidate_object_ids(item, depth - 1))
    return candidates


class BodyObjectReferenceMiddleware(BaseHTTPMiddleware):
    """Intercepts POST, PUT, and PATCH requests, dynamically identifies candidate
    resource identifiers in the JSON body, and verifies object authorization.
    If an unowned foreign resource is referenced, records a body-level BOLA attempt."""
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method in ("POST", "PUT", "PATCH"):
            auth_header = request.headers.get("Authorization", "")
            if auth_header.lower().startswith("bearer "):
                body_bytes = await request.body()
                if body_bytes:
                    try:
                        token = auth_header.split(" ", 1)[1]
                        payload_jwt = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                        subject = payload_jwt["sub"]
                        tenant_id = payload_jwt.get("tenant_id", DEMO_TENANT_ID)

                        data = json.loads(body_bytes)
                        candidates = extract_candidate_object_ids(data)

                        for field_name, cand_id in candidates:
                            if request.url.path.startswith("/auth/") or request.url.path in ("/records/batch", "/hierarchy/access", "/graphql"):
                                continue
                            with db() as c:
                                rec = c.execute(
                                    "SELECT owner_id FROM records WHERE tenant_id = %s AND id = %s",
                                    (tenant_id, cand_id)
                                ).fetchone()
                            if rec:
                                access = authorization_context(tenant_id, subject, cand_id, action="read")
                                if access["authorization"] is None:
                                    engine.evaluate(tenant_id, subject, cand_id, allowed=False, endpoint=f"body_ref:{field_name}")
                                    record_audit(
                                        tenant_id, subject, cand_id, None, "deny", "denied_body_reference",
                                        [f"Unauthorized foreign object ID '{cand_id}' referenced in body field '{field_name}'."]
                                    )
                    except Exception:
                        pass
                    async def receive():
                        return {"type": "http.request", "body": body_bytes}
                    request._receive = receive
        return await call_next(request)

app.add_middleware(BodyObjectReferenceMiddleware)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "env": APP_ENV, "demo_mode": DEMO_MODE, "version": "1.1.1"}


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
        "ml_behavioral_anomaly": "An unsupervised ML model (Isolation Forest) flagged this access pattern as statistically abnormal compared to normal traffic.",
        "unauthorized_write_delete_attempt": "Critical: Unauthorized deletion attempt detected against an object you do not own.",
        "unauthorized_write_mutation_attempt": "Warning: Unauthorized modification (PUT/PATCH) attempt detected against an object you cannot edit.",
        "body_payload_object_injection": "Warning: Unauthorized object references detected embedded within the request body payload.",
        "relational_chain_mismatch": "Warning: Hierarchical parent-child relationship check failed (BOLA path traversal).",
        "second_order_bola_violation": "Warning: Second-order stored reference pointed to an unauthorized or foreign resource.",
        "canary_honeypot_triggered": "CRITICAL: Honeypot canary trap triggered. Instant permanent ban enforced."
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


# ============================================================================
# FEATURE 1: WRITE & MUTATION BOLA (PUT, PATCH, DELETE WITH VERB-WEIGHTING)
# ============================================================================

@app.put("/records/{record_id}")
@limiter.limit("200/minute")
def update_record(
    record_id: str,
    payload: dict,
    request: Request,
    response: Response,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    access = authorization_context(tenant_id, subject, record_id, action="write")
    authorization = access["authorization"]

    decision, signals, unseen, score, category = engine.evaluate(
        tenant_id, subject, record_id, allowed=authorization is not None, endpoint="records_mutation", http_verb="PUT"
    )
    detector_explanations = explain_detector_signals(signals)
    explanations = access["explanations"] + detector_explanations

    response.headers["X-Detector-Decision"] = decision
    response.headers["X-Detector-Signals"] = ",".join(signals)
    response.headers["X-Risk-Score"] = str(score)
    response.headers["X-Risk-Category"] = category

    if decision == "block":
        record_audit(tenant_id, subject, record_id, authorization, decision, "blocked", explanations)
        dispatch_soc_alert(tenant_id, subject, record_id, score, category, signals)
        raise HTTPException(403, detail={"outcome": "blocked", "reason": "BOLA-style behavior detected", "score": score})

    if authorization is None:
        record_audit(tenant_id, subject, record_id, authorization, decision, "denied", explanations)
        raise HTTPException(403, detail={"outcome": "denied", "reason": "No write authorization for record", "score": score})

    new_data = payload.get("data")
    if new_data is None:
        raise HTTPException(400, "data field is required")

    with db() as c:
        c.execute(
            "UPDATE records SET data = %s WHERE tenant_id = %s AND id = %s",
            (str(new_data), tenant_id, str(record_id))
        )
        row = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                        (tenant_id, str(record_id))).fetchone()

    record_audit(tenant_id, subject, record_id, authorization, decision, "allowed_write", explanations)
    return {"status": "updated", "record": dict(row), "score": score}


@app.patch("/records/{record_id}")
@limiter.limit("200/minute")
def patch_record(
    record_id: str,
    payload: dict,
    request: Request,
    response: Response,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    access = authorization_context(tenant_id, subject, record_id, action="patch")
    authorization = access["authorization"]

    decision, signals, unseen, score, category = engine.evaluate(
        tenant_id, subject, record_id, allowed=authorization is not None, endpoint="records_mutation", http_verb="PATCH"
    )
    detector_explanations = explain_detector_signals(signals)
    explanations = access["explanations"] + detector_explanations

    response.headers["X-Detector-Decision"] = decision
    response.headers["X-Detector-Signals"] = ",".join(signals)
    response.headers["X-Risk-Score"] = str(score)
    response.headers["X-Risk-Category"] = category

    if decision == "block":
        record_audit(tenant_id, subject, record_id, authorization, decision, "blocked", explanations)
        dispatch_soc_alert(tenant_id, subject, record_id, score, category, signals)
        raise HTTPException(403, detail={"outcome": "blocked", "reason": "BOLA-style behavior detected", "score": score})

    if authorization is None:
        record_audit(tenant_id, subject, record_id, authorization, decision, "denied", explanations)
        raise HTTPException(403, detail={"outcome": "denied", "reason": "No patch authorization for record", "score": score})

    with db() as c:
        row = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                        (tenant_id, str(record_id))).fetchone()
        if not row:
            raise HTTPException(404, "Record not found")
        patch_text = payload.get("data", f"{row['data']} [patched]")
        c.execute("UPDATE records SET data = %s WHERE tenant_id = %s AND id = %s",
                  (str(patch_text), tenant_id, str(record_id)))
        updated_row = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                                (tenant_id, str(record_id))).fetchone()

    record_audit(tenant_id, subject, record_id, authorization, decision, "allowed_patch", explanations)
    return {"status": "patched", "record": dict(updated_row), "score": score}


@app.delete("/records/{record_id}")
@limiter.limit("100/minute")
def delete_record(
    record_id: str,
    request: Request,
    response: Response,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    access = authorization_context(tenant_id, subject, record_id, action="delete")
    authorization = access["authorization"]

    decision, signals, unseen, score, category = engine.evaluate(
        tenant_id, subject, record_id, allowed=authorization is not None, endpoint="records_mutation", http_verb="DELETE"
    )
    detector_explanations = explain_detector_signals(signals)
    explanations = access["explanations"] + detector_explanations

    response.headers["X-Detector-Decision"] = decision
    response.headers["X-Detector-Signals"] = ",".join(signals)
    response.headers["X-Risk-Score"] = str(score)
    response.headers["X-Risk-Category"] = category

    if decision == "block":
        record_audit(tenant_id, subject, record_id, authorization, decision, "blocked", explanations)
        dispatch_soc_alert(tenant_id, subject, record_id, score, category, signals)
        raise HTTPException(403, detail={"outcome": "blocked", "reason": "BOLA-style behavior detected", "score": score})

    if authorization is None:
        record_audit(tenant_id, subject, record_id, authorization, decision, "denied", explanations)
        raise HTTPException(403, detail={"outcome": "denied", "reason": "Only record owner can delete this record", "score": score})

    with db() as c:
        c.execute("DELETE FROM records WHERE tenant_id = %s AND id = %s", (tenant_id, str(record_id)))

    record_audit(tenant_id, subject, record_id, authorization, decision, "allowed_delete", explanations)
    return {"status": "deleted", "record_id": record_id, "score": score}


# ============================================================================
# FEATURE 2: HIERARCHICAL / PARENT-CHILD RELATIONAL VALIDATION
# ============================================================================

def validate_hierarchical_chain(tenant_id: str, subject: str, chain: list[dict], action: str = "read") -> tuple[bool, list[str], dict | None]:
    """Dynamically validates an arbitrary resource hierarchy chain.
    Ensures:
      1. Every node in chain exists in resource_nodes.
      2. Each child's parent_type and parent_id matches the preceding node (relational integrity).
      3. Subject is authorized for the leaf node."""
    if not chain:
        return False, ["Chain cannot be empty."], None

    with db() as c:
        prev_node = None
        for item in chain:
            r_type = item.get("type")
            r_id = str(item.get("id"))
            node = c.execute(
                "SELECT resource_type, resource_id, parent_type, parent_id, owner_id, name, metadata "
                "FROM resource_nodes WHERE tenant_id = %s AND resource_type = %s AND resource_id = %s",
                (tenant_id, r_type, r_id)
            ).fetchone()
            if not node:
                return False, [f"Node '{r_type}:{r_id}' not found in tenant hierarchy."], None

            if prev_node:
                if node["parent_type"] != prev_node["resource_type"] or node["parent_id"] != prev_node["resource_id"]:
                    return False, [
                        f"Relational chain mismatch: '{r_type}:{r_id}' claims parent '{node['parent_type']}:{node['parent_id']}', "
                        f"which does not match previous chain node '{prev_node['resource_type']}:{prev_node['resource_id']}'."
                    ], None
            prev_node = dict(node)

    leaf = prev_node
    if leaf["resource_type"] == "record":
        rec_access = authorization_context(tenant_id, subject, leaf["resource_id"], action)
        if rec_access["authorization"] is None:
            return False, [f"Access denied to leaf record '{leaf['resource_id']}'."], leaf
    elif leaf["owner_id"] != subject:
        return False, [f"Access denied: you do not own '{leaf['resource_type']}:{leaf['resource_id']}'."], leaf

    return True, ["Hierarchical resource chain successfully verified."], leaf


@app.post("/hierarchy/nodes")
def create_hierarchy_node(
    payload: dict,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    r_type = payload.get("resource_type")
    r_id = str(payload.get("resource_id", ""))
    p_type = payload.get("parent_type")
    p_id = str(payload.get("parent_id")) if payload.get("parent_id") is not None else None
    name = payload.get("name", r_id)
    metadata = json.dumps(payload.get("metadata", {}))

    if not r_type or not r_id:
        raise HTTPException(400, "resource_type and resource_id are required")

    with db() as c:
        c.execute(
            "INSERT INTO resource_nodes (tenant_id, resource_type, resource_id, parent_type, parent_id, owner_id, name, metadata) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (tenant_id, resource_type, resource_id) DO UPDATE SET "
            "parent_type = EXCLUDED.parent_type, parent_id = EXCLUDED.parent_id, "
            "name = EXCLUDED.name, metadata = EXCLUDED.metadata",
            (tenant_id, r_type, r_id, p_type, p_id, subject, name, metadata)
        )
    return {"status": "created", "resource_type": r_type, "resource_id": r_id}


@app.post("/hierarchy/access")
def access_hierarchical_chain(
    payload: dict,
    request: Request,
    response: Response,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    chain = payload.get("chain", [])
    action = payload.get("action", "read")
    if not isinstance(chain, list) or len(chain) == 0:
        raise HTTPException(400, "chain must be a non-empty list of nodes")

    leaf_id = str(chain[-1].get("id", "unknown"))
    valid, explanations, leaf_data = validate_hierarchical_chain(tenant_id, subject, chain, action)

    decision, signals, _unseen, score, category = engine.evaluate(
        tenant_id, subject, leaf_id, allowed=valid, endpoint="hierarchy"
    )
    detector_explanations = explain_detector_signals(signals)
    all_explanations = explanations + detector_explanations

    response.headers["X-Detector-Decision"] = decision
    response.headers["X-Risk-Score"] = str(score)

    if not valid or decision == "block":
        outcome = "blocked" if decision == "block" else "denied"
        record_audit(tenant_id, subject, leaf_id, None, decision, outcome, all_explanations)
        raise HTTPException(403, detail={"outcome": outcome, "reason": "Hierarchical validation failed",
                                         "violations": explanations, "score": score})

    record_audit(tenant_id, subject, leaf_id, "authorized", decision, "allowed", all_explanations)
    return {"outcome": "allowed", "leaf": leaf_data, "chain_length": len(chain), "score": score}


# ============================================================================
# FEATURE 4: BATCH / BULK ARRAY BOLA EVALUATION
# ============================================================================

@app.post("/records/batch")
@limiter.limit("100/minute")
def batch_records(
    payload: dict,
    request: Request,
    response: Response,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    record_ids = payload.get("record_ids", [])
    action = payload.get("action", "read")

    if not isinstance(record_ids, list) or len(record_ids) == 0:
        raise HTTPException(400, "record_ids must be a non-empty list")

    if len(record_ids) > BOLA_MAX_BATCH_SIZE:
        raise HTTPException(400, f"Batch size cannot exceed {BOLA_MAX_BATCH_SIZE} items")

    if engine.blocked_until(tenant_id, subject) > time.time():
        raise HTTPException(403, detail={"outcome": "blocked", "reason": "Subject is blocked"})

    results = []
    allowed_count = 0
    denied_count = 0
    blocked_count = 0
    blocked_mid_batch = False

    for rid in record_ids:
        rid_str = str(rid)
        if engine.blocked_until(tenant_id, subject) > time.time():
            blocked_mid_batch = True
            blocked_count += 1
            results.append({"record_id": rid_str, "status": "blocked_mid_batch", "data": None})
            continue

        access = authorization_context(tenant_id, subject, rid_str, action)
        decision, signals, _unseen, score, category = engine.evaluate(
            tenant_id, subject, rid_str, allowed=access["authorization"] is not None, endpoint="records_batch"
        )

        if decision == "block":
            blocked_mid_batch = True
            blocked_count += 1
            results.append({"record_id": rid_str, "status": "blocked", "score": score, "signals": signals})
        elif access["authorization"] is None:
            denied_count += 1
            results.append({"record_id": rid_str, "status": "denied", "score": score, "signals": signals})
        else:
            allowed_count += 1
            with db() as c:
                row = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                                (tenant_id, rid_str)).fetchone()
            results.append({"record_id": rid_str, "status": "allowed", "data": dict(row) if row else None, "score": score})

    return {
        "total": len(record_ids),
        "allowed": allowed_count,
        "denied": denied_count,
        "blocked": blocked_count,
        "blocked_mid_batch": blocked_mid_batch,
        "results": results
    }


# ============================================================================
# FEATURE 5: ASYNCHRONOUS BACKGROUND JOB CONTEXT PROPAGATION
# ============================================================================

def generate_job_proof(tenant_id: str, subject: str, resource_id: str, action: str, expires_at: float) -> str:
    message = f"{tenant_id}:{subject}:{resource_id}:{action}:{round(expires_at, 2)}"
    return hmac.new(JWT_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()


def execute_async_job(job_id: str) -> dict:
    """Worker execution: verifies cryptographic HMAC pre-authorization proof and TTL before executing."""
    with db() as c:
        job = c.execute(
            "SELECT id, tenant_id, subject_id, resource_id, action, pre_authorized, pre_auth_token, status, expires_at "
            "FROM async_jobs WHERE id = %s", (job_id,)
        ).fetchone()

    if not job:
        return {"status": "failed", "error": "Job not found"}

    now = time.time()
    expected_proof = generate_job_proof(job["tenant_id"], job["subject_id"], job["resource_id"], job["action"], job["expires_at"])

    if not hmac.compare_digest(job["pre_auth_token"], expected_proof) or not job["pre_authorized"]:
        with db() as c:
            c.execute("UPDATE async_jobs SET status = 'security_violation' WHERE id = %s", (job_id,))
        engine.evaluate(job["tenant_id"], job["subject_id"], job["resource_id"], allowed=False, endpoint="async_jobs")
        return {"status": "security_violation", "error": "Cryptographic pre-authorization signature mismatch"}

    if now > job["expires_at"]:
        with db() as c:
            c.execute("UPDATE async_jobs SET status = 'expired' WHERE id = %s", (job_id,))
        return {"status": "expired", "error": "Pre-authorization context expired"}

    with db() as c:
        record = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                           (job["tenant_id"], job["resource_id"])).fetchone()
        res_data = json.dumps(dict(record)) if record else "{}"
        c.execute("UPDATE async_jobs SET status = 'completed', completed_at = %s, result_payload = %s WHERE id = %s",
                  (now, res_data, job_id))

    return {"status": "completed", "job_id": job_id, "result": json.loads(res_data)}


@app.post("/jobs")
def create_job(
    payload: dict,
    request: Request,
    response: Response,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    resource_id = str(payload.get("resource_id", ""))
    action = payload.get("action", "export")

    if not resource_id:
        raise HTTPException(400, "resource_id required")

    access = authorization_context(tenant_id, subject, resource_id, action="read")
    if access["authorization"] is None:
        decision, signals, _unseen, score, category = engine.evaluate(
            tenant_id, subject, resource_id, allowed=False, endpoint="async_jobs"
        )
        record_audit(tenant_id, subject, resource_id, None, decision, "denied_job", access["explanations"])
        raise HTTPException(403, detail={"outcome": "denied", "reason": "No authorization to enqueue job for requested resource", "score": score})

    job_id = f"job_{secrets.token_hex(8)}"
    now = time.time()
    expires_at = now + BOLA_ASYNC_JOB_TTL
    token = generate_job_proof(tenant_id, subject, resource_id, action, expires_at)

    with db() as c:
        c.execute(
            "INSERT INTO async_jobs (id, tenant_id, subject_id, resource_id, action, pre_authorized, pre_auth_token, status, created_at, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', %s, %s)",
            (job_id, tenant_id, subject, resource_id, action, True, token, now, expires_at)
        )
    return {"job_id": job_id, "status": "pending", "expires_at": expires_at}


@app.get("/jobs/{job_id}")
def get_job_status(
    job_id: str,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    with db() as c:
        job = c.execute(
            "SELECT id, tenant_id, subject_id, resource_id, action, status, created_at, expires_at, completed_at, result_payload "
            "FROM async_jobs WHERE id = %s AND tenant_id = %s AND subject_id = %s",
            (job_id, tenant_id, subject)
        ).fetchone()
    if not job:
        raise HTTPException(404, "Job not found")
    res = dict(job)
    if res.get("result_payload"):
        try:
            res["result_payload"] = json.loads(res["result_payload"])
        except Exception:
            pass
    return res


@app.post("/jobs/{job_id}/execute")
def trigger_worker_execution(
    job_id: str,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    return execute_async_job(job_id)


# ============================================================================
# FEATURE 7: SECOND-ORDER STORED BOLA VALIDATION
# ============================================================================

@app.post("/stored-references")
def create_stored_reference(
    payload: dict,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    ref_type = payload.get("ref_type", "webhook")
    target_id = str(payload.get("target_resource_id", ""))
    metadata = json.dumps(payload.get("metadata", {}))

    if not target_id:
        raise HTTPException(400, "target_resource_id required")

    access = authorization_context(tenant_id, subject, target_id, action="read")
    if access["authorization"] is None:
        engine.evaluate(tenant_id, subject, target_id, allowed=False, endpoint="stored_ref")
        record_audit(tenant_id, subject, target_id, None, "deny", "denied_stored_bola_creation",
                     ["Second-order BOLA violation: Cannot register reference to unauthorized resource."])
        raise HTTPException(403, detail={"outcome": "denied", "reason": "Second-order BOLA prevented: Cannot store pointer to unowned resource",
                                         "attack_type": "second_order_bola"})

    ref_id = f"ref_{secrets.token_hex(8)}"
    now = time.time()
    with db() as c:
        c.execute(
            "INSERT INTO stored_references (id, tenant_id, subject_id, ref_type, target_resource_id, metadata, authorized_at_creation, created_at, status) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'active')",
            (ref_id, tenant_id, subject, ref_type, target_id, metadata, True, now)
        )
    return {"ref_id": ref_id, "status": "active", "target_resource_id": target_id}


@app.post("/stored-references/{ref_id}/trigger")
def trigger_stored_reference(
    ref_id: str,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, _role, tenant_id = identity
    with db() as c:
        ref = c.execute(
            "SELECT id, tenant_id, subject_id, ref_type, target_resource_id, status FROM stored_references WHERE id = %s AND tenant_id = %s",
            (ref_id, tenant_id)
        ).fetchone()

    if not ref:
        raise HTTPException(404, "Stored reference not found")

    target_id = ref["target_resource_id"]
    access = authorization_context(tenant_id, ref["subject_id"], target_id, action="read")
    now = time.time()

    if access["authorization"] is None:
        with db() as c:
            c.execute("UPDATE stored_references SET status = 'security_flagged' WHERE id = %s", (ref_id,))
        engine.evaluate(tenant_id, ref["subject_id"], target_id, allowed=False, endpoint="stored_ref")
        record_audit(tenant_id, ref["subject_id"], target_id, None, "deny", "denied_stored_bola_consumption",
                     ["Second-order BOLA detected at trigger time: authorization has lapsed or resource changed owners."])
        raise HTTPException(403, detail={"outcome": "denied", "reason": "Second-order BOLA prevented at consumption time",
                                         "ref_status": "security_flagged"})

    with db() as c:
        c.execute("UPDATE stored_references SET last_validated_at = %s WHERE id = %s", (now, ref_id))
    return {"status": "triggered", "ref_id": ref_id, "target_resource_id": target_id, "validated_at": now}


# ============================================================================
# FEATURE 8: DYNAMIC ABAC & FIELD-LEVEL REDACTION
# ============================================================================

def evaluate_dynamic_abac(tenant_id: str, subject: str, role: str, record_id: str,
                          record_dict: dict, hour: int | None = None, clearance: int = 0) -> tuple[bool, list[str]]:
    """Evaluates dynamic ABAC rules stored in abac_policies for the tenant."""
    now_hour = hour if hour is not None else time.localtime().tm_hour
    classification = record_dict.get("classification", "standard")

    with db() as c:
        policies = c.execute(
            "SELECT id, name, effect, target_role, target_classification, min_clearance, allowed_hours_start, allowed_hours_end "
            "FROM abac_policies WHERE tenant_id = %s", (tenant_id,)
        ).fetchall()

    for pol in policies:
        if pol["target_role"] and pol["target_role"] != role:
            continue
        if pol["target_classification"] and pol["target_classification"] != classification:
            continue
        if not (pol["allowed_hours_start"] <= now_hour <= pol["allowed_hours_end"]):
            return False, [f"Access denied by ABAC policy '{pol['name']}': Access restricted outside {pol['allowed_hours_start']}:00 - {pol['allowed_hours_end']}:00."]
        if clearance < pol["min_clearance"]:
            return False, [f"Access denied by ABAC policy '{pol['name']}': Requires minimum clearance level {pol['min_clearance']}."]

    return True, ["ABAC policy evaluation passed."]


def apply_dynamic_field_redaction(tenant_id: str, resource_type: str, data_dict: dict,
                                   role: str, clearance: int = 0) -> tuple[dict, list[str]]:
    """Applies dynamic field-level masking based on abac_field_redactions table."""
    with db() as c:
        rules = c.execute(
            "SELECT field_name, required_role, min_clearance, masking_strategy FROM abac_field_redactions "
            "WHERE tenant_id = %s AND resource_type = %s", (tenant_id, resource_type)
        ).fetchall()

    redacted = dict(data_dict)
    redacted_fields = []

    for rule in rules:
        fname = rule["field_name"]
        if fname in redacted:
            meets_role = (role == rule["required_role"]) or (role == ADMIN_ROLE)
            meets_clearance = (role == ADMIN_ROLE) or (clearance >= rule["min_clearance"])
            if not (meets_role and meets_clearance):
                strategy = rule["masking_strategy"]
                if strategy == "HASH":
                    redacted[fname] = hashlib.sha256(str(redacted[fname]).encode()).hexdigest()[:12] + "..."
                else:
                    redacted[fname] = "[REDACTED]"
                redacted_fields.append(fname)

    return redacted, redacted_fields


@app.get("/records/{record_id}/abac")
def get_record_abac(
    record_id: str,
    request: Request,
    response: Response,
    clearance: int = 0,
    hour: int | None = None,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, role, tenant_id = identity

    access = authorization_context(tenant_id, subject, record_id, action="read")
    if access["authorization"] is None:
        engine.evaluate(tenant_id, subject, record_id, allowed=False, endpoint="records_abac")
        raise HTTPException(403, detail={"outcome": "denied", "reason": "No object-level authorization"})

    with db() as c:
        row = c.execute("SELECT id, owner_id, data, classification FROM records WHERE tenant_id = %s AND id = %s",
                        (tenant_id, str(record_id))).fetchone()
    if not row:
        raise HTTPException(404, "Record not found")

    rec_dict = dict(row)
    abac_pass, abac_reasons = evaluate_dynamic_abac(tenant_id, subject, role, record_id, rec_dict, hour=hour, clearance=clearance)
    if not abac_pass:
        engine.evaluate(tenant_id, subject, record_id, allowed=False, endpoint="records_abac")
        raise HTTPException(403, detail={"outcome": "denied", "reason": "ABAC policy restriction", "violations": abac_reasons})

    data_content = rec_dict.get("data", "")
    try:
        structured_data = json.loads(data_content)
    except Exception:
        structured_data = {"notes": data_content, "psychiatric_notes": "Clinical mental evaluation details", "ssn": "000-12-3456"}

    redacted_data, redacted_fields = apply_dynamic_field_redaction(tenant_id, "record", structured_data, role, clearance)
    rec_dict["data"] = redacted_data

    engine.evaluate(tenant_id, subject, record_id, allowed=True, endpoint="records_abac")
    return {
        "record": rec_dict,
        "abac_verified": True,
        "redacted_fields": redacted_fields,
        "authorization": access["authorization"]
    }


@app.post("/admin/abac/policies")
def add_abac_policy(
    payload: dict,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, role, tenant_id = identity
    require_security_admin(role)
    pol_id = str(payload.get("id", f"pol_{secrets.token_hex(6)}"))
    name = payload.get("name", "Custom Policy")
    effect = payload.get("effect", "allow")
    target_role = payload.get("target_role")
    target_class = payload.get("target_classification")
    min_clear = int(payload.get("min_clearance", 0))
    start_hour = int(payload.get("allowed_hours_start", 0))
    end_hour = int(payload.get("allowed_hours_end", 24))

    with db() as c:
        c.execute(
            "INSERT INTO abac_policies (id, tenant_id, name, effect, target_role, target_classification, min_clearance, allowed_hours_start, allowed_hours_end, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, effect = EXCLUDED.effect, "
            "target_role = EXCLUDED.target_role, target_classification = EXCLUDED.target_classification, "
            "min_clearance = EXCLUDED.min_clearance, allowed_hours_start = EXCLUDED.allowed_hours_start, "
            "allowed_hours_end = EXCLUDED.allowed_hours_end",
            (pol_id, tenant_id, name, effect, target_role, target_class, min_clear, start_hour, end_hour, time.time())
        )
    return {"status": "policy_saved", "id": pol_id}


@app.post("/admin/abac/redactions")
def add_abac_redaction(
    payload: dict,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, role, tenant_id = identity
    require_security_admin(role)
    rule_id = str(payload.get("id", f"red_{secrets.token_hex(6)}"))
    res_type = payload.get("resource_type", "record")
    f_name = payload.get("field_name")
    req_role = payload.get("required_role")
    min_clear = int(payload.get("min_clearance", 0))
    strat = payload.get("masking_strategy", "REDACT")

    if not f_name:
        raise HTTPException(400, "field_name required")

    with db() as c:
        c.execute(
            "INSERT INTO abac_field_redactions (id, tenant_id, resource_type, field_name, required_role, min_clearance, masking_strategy) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (id) DO UPDATE SET resource_type = EXCLUDED.resource_type, "
            "field_name = EXCLUDED.field_name, required_role = EXCLUDED.required_role, "
            "min_clearance = EXCLUDED.min_clearance, masking_strategy = EXCLUDED.masking_strategy",
            (rule_id, tenant_id, res_type, f_name, req_role, min_clear, strat)
        )
    return {"status": "redaction_rule_saved", "id": rule_id}


# ============================================================================
# FEATURE 9: CANARY / HONEYPOT DECOY MANAGEMENT ENDPOINTS
# ============================================================================

@app.post("/admin/canaries")
def add_canary_record(
    payload: dict,
    identity: tuple[str, str, str] = Depends(get_current_identity),
) -> dict:
    subject, role, tenant_id = identity
    require_security_admin(role)
    canary_id = str(payload.get("id", ""))
    decoy_name = payload.get("decoy_name", "Decoy Trap Record")
    severity = payload.get("severity", "CRITICAL")
    trap_action = payload.get("trap_action", "PERMANENT_BAN")

    if not canary_id:
        raise HTTPException(400, "id is required")

    with db() as c:
        c.execute(
            "INSERT INTO canary_records (tenant_id, id, decoy_name, severity, trap_action, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (tenant_id, id) DO UPDATE SET "
            "decoy_name = EXCLUDED.decoy_name, severity = EXCLUDED.severity, trap_action = EXCLUDED.trap_action",
            (tenant_id, canary_id, decoy_name, severity, trap_action, time.time())
        )
    return {"status": "canary_registered", "id": canary_id}


@app.get("/admin/canaries")
def list_canaries(identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    subject, role, tenant_id = identity
    require_security_admin(role)
    with db() as c:
        rows = c.execute("SELECT id, decoy_name, severity, trap_action, created_at FROM canary_records WHERE tenant_id = %s",
                         (tenant_id,)).fetchall()
    return {"canaries": [dict(r) for r in rows]}


@app.get("/admin/canary-triggers")
def list_canary_triggers(identity: tuple[str, str, str] = Depends(get_current_identity)) -> dict:
    subject, role, tenant_id = identity
    require_security_admin(role)
    with db() as c:
        rows = c.execute(
            "SELECT id, canary_id, subject_id, endpoint, ip_address, triggered_at, action_taken "
            "FROM canary_triggers WHERE tenant_id = %s ORDER BY triggered_at DESC LIMIT 100",
            (tenant_id,)
        ).fetchall()
    return {"triggers": [dict(r) for r in rows]}


# ============================================================================
# FEATURE 6: STRAWBERRY GRAPHQL TRAVERSAL & RESOLVER HOOKS
# ============================================================================

def _extract_gql_identity(request: Request) -> tuple[str, str, str]:
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        raise PermissionError("Authentication required: missing Bearer token")
    token = auth.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["sub"], payload.get("role", "customer"), payload.get("tenant_id", DEMO_TENANT_ID)
    except Exception as e:
        raise PermissionError(f"Invalid authentication token: {str(e)}")


@strawberry.type
class GraphQLRecordNode:
    id: str
    owner_id: str
    data: str


@strawberry.type
class GraphQLQuery:
    @strawberry.field
    def record(self, info: strawberry.Info, id: str) -> GraphQLRecordNode | None:
        request: Request = info.context["request"]
        subject, _role, tenant_id = _extract_gql_identity(request)

        # Canary check
        if is_canary_record(tenant_id, id):
            trigger_canary_trap(tenant_id, subject, id, endpoint="graphql")
            raise PermissionError("Access denied to requested record")

        access = authorization_context(tenant_id, subject, id, action="read")
        decision, signals, _unseen, score, category = engine.evaluate(
            tenant_id, subject, id, allowed=access["authorization"] is not None, endpoint="graphql"
        )
        if access["authorization"] is None or decision == "block":
            record_audit(tenant_id, subject, id, None, decision, "denied_graphql", access["explanations"])
            raise PermissionError(f"Access denied to record '{id}': No object authorization")

        with db() as c:
            row = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                            (tenant_id, str(id))).fetchone()
        if not row:
            return None
        return GraphQLRecordNode(id=row["id"], owner_id=row["owner_id"], data=row["data"])

    @strawberry.field
    def records(self, info: strawberry.Info, ids: list[str]) -> list[GraphQLRecordNode]:
        request: Request = info.context["request"]
        subject, _role, tenant_id = _extract_gql_identity(request)
        nodes = []
        for rid in ids:
            if is_canary_record(tenant_id, rid):
                trigger_canary_trap(tenant_id, subject, rid, endpoint="graphql")
                continue
            access = authorization_context(tenant_id, subject, rid, action="read")
            engine.evaluate(tenant_id, subject, rid, allowed=access["authorization"] is not None, endpoint="graphql")
            if access["authorization"] is not None:
                with db() as c:
                    row = c.execute("SELECT id, owner_id, data FROM records WHERE tenant_id = %s AND id = %s",
                                    (tenant_id, str(rid))).fetchone()
                if row:
                    nodes.append(GraphQLRecordNode(id=row["id"], owner_id=row["owner_id"], data=row["data"]))
        return nodes


graphql_schema = strawberry.Schema(query=GraphQLQuery)
app.include_router(GraphQLRouter(graphql_schema), prefix="/graphql")


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
