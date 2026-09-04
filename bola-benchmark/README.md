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

## 🧪 Running Security Test Suite

Run the 24 automated unit and security scenario tests:

```bash
pytest test_detector.py -v
```

## 📁 Key Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/records/{record_id}` | Fetch a record (Evaluates Layer 1 Auth + Layer 2 Risk) |
| `GET` | `/audit-events` | View recent authorization audit logs (`security_admin` only) |
| `GET` | `/risk/{subject}` | Inspect real-time risk score and signals for a user |
| `GET` | `/stats` | Telemetry overview: active subjects, blocked actors, attacks |
| `POST` | `/simulate/rapid` | Run simulated rapid BOLA fuzzing attack |
| `POST` | `/simulate/low_and_slow` | Run simulated stealth reconnaissance attack |
| `POST` | `/reset` | Reset SQLite database and in-memory sliding windows |
