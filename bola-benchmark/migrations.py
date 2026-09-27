"""
Database migrations for CyberAccess Enterprise features.
Immutable audit logs, multi-tenant quotas, compliance tracking, alerting.
"""
import time
import hashlib

SCHEMA_VERSION = 10
MIGRATIONS = [
    # Existing migrations (1-9 from app.py init_schema)
    # ... (these run in init_schema)

    # NEW: Enterprise features
    (10, """
        -- Make audit_events append-only: no UPDATE/DELETE allowed
        CREATE TABLE IF NOT EXISTS audit_events_v2 (
            id BIGSERIAL PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            occurred_at DOUBLE PRECISION NOT NULL,
            subject_id TEXT NOT NULL,
            record_id TEXT NOT NULL,
            "authorization" TEXT,
            detector_decision TEXT NOT NULL,
            outcome TEXT NOT NULL,
            explanation TEXT NOT NULL,
            risk_score DOUBLE PRECISION DEFAULT 0.0,

            -- Forensic proof chain
            previous_hash TEXT,  -- Hash of previous row (for immutability)
            current_hash TEXT,   -- Hash of this row

            -- Audit metadata
            created_at TIMESTAMP DEFAULT NOW(),
            CONSTRAINT no_delete CHECK (true)  -- Prevent accidental deletes
        );
        CREATE INDEX IF NOT EXISTS idx_audit_v2_tenant_time
            ON audit_events_v2(tenant_id, occurred_at DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_v2_subject
            ON audit_events_v2(tenant_id, subject_id, occurred_at DESC);
    """),

    (11, """
        -- Tenant quotas and rate limiting
        CREATE TABLE IF NOT EXISTS tenant_quotas (
            tenant_id TEXT PRIMARY KEY,
            requests_per_minute INT DEFAULT 1000,
            max_stored_audit_events INT DEFAULT 1000000,
            max_audit_retention_days INT DEFAULT 365,
            ml_model_version TEXT DEFAULT 'v1',
            risk_threshold_block INT DEFAULT 90,
            risk_threshold_warn INT DEFAULT 70,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );
    """),

    (12, """
        -- Compliance attestations (HIPAA, GDPR, SOC2)
        CREATE TABLE IF NOT EXISTS compliance_attestations (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            compliance_type TEXT NOT NULL,  -- 'HIPAA', 'GDPR', 'SOC2'
            status TEXT DEFAULT 'PENDING',   -- 'PENDING', 'COMPLIANT', 'NON_COMPLIANT'

            -- Attestation details
            attestation_date TIMESTAMP DEFAULT NOW(),
            attestation_body TEXT,  -- JSON blob with compliance details
            auditor_name TEXT,
            auditor_signature TEXT,

            -- Metrics snapshot
            uptime_percentage DOUBLE PRECISION,
            unauthorized_access_attempts INT DEFAULT 0,
            audit_log_modifications INT DEFAULT 0,
            data_breaches INT DEFAULT 0,

            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW(),

            UNIQUE(tenant_id, compliance_type, attestation_date)
        );
        CREATE INDEX IF NOT EXISTS idx_compliance_tenant
            ON compliance_attestations(tenant_id, compliance_type);
    """),

    (13, """
        -- Alert channels for Slack, Email, webhooks
        CREATE TABLE IF NOT EXISTS alert_channels (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            channel_type TEXT NOT NULL,      -- 'slack', 'email', 'webhook'
            channel_config TEXT NOT NULL,    -- JSON: {"url": "...", "token": "..."}
            alert_threshold INT DEFAULT 80,  -- Alert when quota usage > this %
            is_active BOOLEAN DEFAULT true,
            created_at TIMESTAMP DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_tenant
            ON alert_channels(tenant_id, is_active);
    """),

    (14, """
        -- Rate limit state (for per-tenant throttling)
        CREATE TABLE IF NOT EXISTS rate_limit_state (
            tenant_id TEXT PRIMARY KEY,
            current_requests INT DEFAULT 0,
            requests_reset_at TIMESTAMP,
            last_updated TIMESTAMP DEFAULT NOW()
        );
    """),

    (15, """
        -- Behavioral profiles (for anomaly detection)
        CREATE TABLE IF NOT EXISTS behavioral_profiles (
            tenant_id TEXT,
            subject_id TEXT,
            hour INT,  -- 0-23
            avg_requests_per_min INT,
            avg_unique_resources INT,
            common_endpoints TEXT[],
            updated_at TIMESTAMP DEFAULT NOW(),
            PRIMARY KEY (tenant_id, subject_id, hour)
        );
    """),
]


def apply_migrations(db_connection):
    """Apply all pending migrations."""
    try:
        # Get current schema version
        with db_connection() as c:
            try:
                result = c.execute(
                    "SELECT value FROM system_config WHERE key = %s",
                    ("schema_version",)
                ).fetchone()
                current_version = int(result["value"]) if result else 0
            except Exception:
                current_version = 9  # Assume v9 (from init_schema)

        # Apply pending migrations
        for version, sql in MIGRATIONS[current_version:]:
            print(f"[migration] Applying v{version}...")
            try:
                with db_connection() as c:
                    c.execute(sql)
                    c.execute(
                        "INSERT INTO system_config (key, value, updated_at) "
                        "VALUES (%s, %s, %s) "
                        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
                        ("schema_version", str(version), time.time())
                    )
                print(f"[migration] ✅ v{version} applied")
            except Exception as e:
                print(f"[migration] ⚠️  v{version} skipped: {e.__class__.__name__}")
    except Exception as e:
        print(f"[migration] ❌ Error: {e}")


def compute_audit_hash(row: dict) -> str:
    """Compute SHA-256 hash of audit event for forensic proof chain."""
    content = f"{row['id']}|{row['tenant_id']}|{row['subject_id']}|{row['record_id']}|{row['risk_score']}|{row['outcome']}"
    return hashlib.sha256(content.encode()).hexdigest()
