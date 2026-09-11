# Backend API: BOLA Benchmark & Detection Engine

FastAPI-powered backend implementing **Layer 1 (Deterministic SQL Authorization)** and **Layer 2 (Behavioral Risk Engine)**.

## 🚀 Getting Started

### 1. Setup Environment
```bash
python -m venv .venv

# Windows:
.\.venv\Scripts\activate
# Linux / macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Run the Server
```bash
uvicorn app:app --port 8000 --reload
```

* **API Docs (Swagger UI):** `http://127.0.0.1:8000/docs`
* **OpenAPI Schema:** `http://127.0.0.1:8000/openapi.json`

### 3. Authenticate

All object-access and admin endpoints require a JWT bearer token — the old
`X-Subject` header is gone. Every seeded demo account shares one password:

```bash
curl -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"subject": "alice", "password": "changeme123"}'
# -> {"access_token": "...", "token_type": "bearer", "role": "customer", ...}

curl http://127.0.0.1:8000/records/1 -H "Authorization: Bearer <access_token>"
```

New identities register first via `POST /auth/register` (`{"subject", "password", "role"}`).
The `security_admin` account (needed for `/audit-events`, `/admin/*`, `/soc/*`) uses a
separate password — `ADMIN_PASSWORD` env var, default `admin_changeme123`.

Override the dev-only defaults via environment variables before running in anything
beyond a local sandbox: `JWT_SECRET`, `DEMO_PASSWORD`, `ADMIN_PASSWORD`.

## 🧪 Running Security Test Suite

Run the automated unit and security scenario tests:

```bash
pytest test_detector.py -v
```

## 📈 Running the Reproducible Benchmark

`benchmark.py` runs every scenario in `EXTERNAL_VALIDATION.md` in-process (no server needed) and writes evidence to `results/`:

```bash
python benchmark.py
```

* `results/events.csv` — every request issued by the run (subject, record, status, decision, risk score, latency)
* `results/metrics.json` — pass/fail per scenario plus `requests_to_first_block` (detection latency)
* `results/warmup_curve.csv` — a fresh identity's risk score after each successive unauthorized request, showing how many requests it takes to escalate Normal → Suspicious → High Risk → Attack

`results/` is untracked (see `.gitignore`) since it's regenerated output, not source.

## 📁 Key Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/auth/register` | Register a new identity (`subject`, `password`, optional `role`) |
| `POST` | `/auth/login` | Exchange credentials for a JWT bearer token |
| `GET` | `/records/{record_id}` | Fetch a record (Evaluates Layer 1 Auth + Layer 2 Risk). Requires a bearer token. |
| `GET` | `/audit-events` | View recent authorization audit logs (`security_admin` role only) |
| `GET` | `/risk/{subject}` | Inspect real-time risk score and signals for a user (per-subject `IsolationForest`, synthetic-trained) |
| `GET` | `/records/{record_id}/graph-risk` | Per-endpoint access-graph anomaly score from a second model (`RandomForestClassifier`, trained on real Kaggle-labeled data — see `train_endpoint_anomaly_model.py`). Diagnostic signal, not an allow/deny gate. Requires a bearer token. |
| `GET` | `/stats` | Telemetry overview: active subjects, blocked actors, attacks |
| `POST` | `/admin/approve-ban/{subject}` / `/admin/reject-ban/{subject}` | HITL Strike-3 ban approval (`security_admin` role only) |
| `GET` | `/soc/alerts` | SIEM-style forensic alert feed (`security_admin` role only) |
| `POST` | `/simulate/rapid` | Run simulated rapid BOLA fuzzing attack |
| `POST` | `/simulate/low_and_slow` | Run simulated stealth reconnaissance attack |
| `POST` | `/reset` | Reset demo dataset and persistent risk-engine state (audit log untouched) |
