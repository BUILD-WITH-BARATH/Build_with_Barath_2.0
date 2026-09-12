# CyberAccess Integration Test & Verification

## Quick Start (Full Stack)

### Option 1: Docker Compose (Recommended)
```bash
cd D:\Build_with_Barath_2.0
docker compose up --build
```

This brings up:
- **PostgreSQL**: Port 5432 (localhost)
- **FastAPI Backend**: Port 8000 (http://localhost:8000)
- **React Frontend**: Port 5173 → Port 80 in nginx (http://localhost:5173)

Wait for all services to be healthy (check logs for "listening" messages).

---

### Option 2: Manual Local Development

#### 1. Start Backend
```bash
cd bola-benchmark
source .venv/Scripts/activate  # Windows: .\.venv\Scripts\activate.bat
export DEMO_MODE=true
export APP_ENV=dev
export FRONTEND_ORIGIN="http://localhost:5173,http://127.0.0.1:5173"
uvicorn app:app --reload --port 8000
```

Expected output:
```
Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

#### 2. Start Frontend (in new terminal)
```bash
cd bola-frontend
npm install  # if not already done
npm run dev
```

Expected output:
```
VITE v8.2.2  ready in XXX ms

➜  Local:   http://localhost:5173/
➜  Press h to show help
```

#### 3. Verify Backend is Running
```bash
curl -s http://localhost:8000/health | jq .
```

Expected response:
```json
{
  "status": "healthy",
  "version": "1.1.1"
}
```

---

## Integration Verification Checklist

### ✅ Frontend → Backend API Connectivity

Test each endpoint the frontend depends on:

```bash
# 1. Auth Endpoint
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"subject":"security_admin","password":"admin_changeme123"}' | jq .
# Should return: { "access_token": "eyJ...", "token_type": "bearer" }

# 2. Config Endpoint
curl http://localhost:8000/config | jq .
# Should return: { "short_window": 30, "long_window": 3600, ... }

# 3. Stats Endpoint
curl http://localhost:8000/stats | jq .
# Should return: { "active_subjects": 0, "blocked_subjects": 0, ... }

# 4. Risk Endpoint
curl http://localhost:8000/risk/alice | jq .
# Should return: { "subject": "alice", "score": 0, "category": "Normal", ... }

# 5. Events Endpoint (Requires auth token)
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"subject":"security_admin","password":"admin_changeme123"}' | jq -r .access_token)
curl http://localhost:8000/events \
  -H "Authorization: Bearer $TOKEN" | jq .
# Should return: [ { "id": 1, "occurred_at": ..., ... } ]

# 6. Simulation Endpoint
curl -X POST http://localhost:8000/redteam/campaign \
  -H "Content-Type: application/json" \
  -d '{"attack_type":"rapid","subject":"attacker_1","count":5}' | jq .
# Should return: { "campaign_id": "...", "status": "completed", ... }
```

### ✅ CORS Verification

Frontend should be able to call backend without CORS errors:

```bash
# Check CORS headers
curl -v http://localhost:8000/config \
  -H "Origin: http://localhost:5173"
```

Expected headers:
```
< Access-Control-Allow-Origin: *
< Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
< Access-Control-Allow-Headers: *
```

### ✅ Frontend Functionality

Open browser and test:

1. **Dashboard Load**
   - URL: http://localhost:5173
   - Expected: React dashboard loads without console errors
   - Check DevTools Network tab: All XHR requests to `/config`, `/stats` should succeed (200)

2. **Threat Radar**
   - Should show "0 active subjects, 0 blocked"
   - Live updates every 3 seconds

3. **Risk Assessment**
   - Type subject name: "alice"
   - Click "Assess Risk"
   - Should show risk score, signals, explanations

4. **Simulation**
   - Select attack type (Rapid/Low-and-Slow/Sybil)
   - Click "Simulate"
   - Should complete in <2 seconds

5. **Audit Timeline (NEW)**
   - Right side panel: "AUDIT TIMELINE"
   - Should show real-time security events: 404 probes, blocks, denials
   - 404 probes appear in **violet** with "404 PROBE" label
   - Canary traps appear in **pink** with "CANARY" label
   - Blocked attempts appear in **red** with "BLOCKED" label

---

## Lost-foundbyKM Integration

### ✅ Environment Setup

Copy `.env.example` to `.env` and configure:

```bash
cd Lost-foundbyKM
cp .env.example .env
```

Edit `.env`:
```
CYBERACCESS_ENABLED=true
CYBERACCESS_API_URL=http://127.0.0.1:8000  # Local dev
CYBERACCESS_API_KEY=sk_live_xxxxx_your_key  # Get from CyberAccess admin
CYBERACCESS_FAIL_OPEN=true
CYBERACCESS_TIMEOUT=2.0
CYBERACCESS_CANARIES=0,999999,canary_admin_vault
```

### ✅ Start Django App

```bash
cd Lost-foundbyKM
source .venv/Scripts/activate
python manage.py migrate
python manage.py runserver 0.0.0.0:8001
```

### ✅ Test Audit Timeline (404 Probes)

While Lost-foundbyKM is running, trigger 404 probes and watch the timeline:

```bash
# From another terminal, trigger 404 probes
curl http://localhost:8001/item/999  # Non-existent item
curl http://localhost:8001/items/888  # Another non-existent item
curl http://localhost:8001/claim/777  # Non-existent claim
```

Expected results on dashboard:
1. Each 404 probe appears in Audit Timeline within 3 seconds
2. Marked as "404 PROBE" in **violet**
3. Shows subject (IP or username) and resource ID
4. Timestamp updates in real-time

### ✅ Test BOLA Protection

```bash
# Run the integration test
python test_cyberaccess_defense.py
```

Expected output:
```
======================================================================
[*] RUNNING CYBERACCESS BOLA DEFENSE VERIFICATION SUITE
======================================================================
[TEST 1] Authorized User: Alice accesses her own claim...
  [OK] Access GRANTED: Alice successfully viewed her claim (HTTP 200).
[TEST 2] Attacker probes single unowned item edit page...
  [DENIED] Layer 1 Gate Denied: Attacker redirected away without data leak.
[TEST 3] Simulating Rapid BOLA Enumeration Attack...
  [ALERT] THREAT NEUTRALIZED! CyberAccess 3-Strike Lockout triggered!
[TEST 4] Testing Canary Honeypot Trap...
  [ALERT] CANARY TRIPPED: Instant lockout response rendered with HTTP 403.
======================================================================
[SUCCESS] ALL CYBERACCESS INTEGRATION TESTS PASSED SUCCESSFULLY!
======================================================================
```

---

## Troubleshooting

### Frontend Shows "API Unreachable"

**Check:**
1. Backend is running: `curl http://localhost:8000/health`
2. Frontend API base URL is correct:
   - Local dev: `http://127.0.0.1:8000`
   - Docker: `http://backend:8000` (internal DNS)
3. CORS is enabled: Check `docker-compose.yml` or `app.py` line 1098

**Fix:**
```bash
# Verify Docker networking
docker network inspect build_with_barath_2-0_default
# Should show both 'backend' and 'frontend' containers

# Or locally, restart both:
pkill -f "uvicorn"  # Kill backend
pkill -f "npm run dev"  # Kill frontend
# Then restart both per Option 2 above
```

### Backend Returns 401 Unauthorized

**Check:**
1. JWT secret is set: `echo $JWT_SECRET`
2. Token is in Authorization header: `Authorization: Bearer <token>`
3. Admin password matches `.env`: `ADMIN_PASSWORD=admin_changeme123`

**Fix:**
```bash
# Get a fresh token
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"subject":"security_admin","password":"admin_changeme123"}' | jq -r .access_token)

# Use it
curl http://localhost:8000/events -H "Authorization: Bearer $TOKEN"
```

### Lost-foundbyKM Returns 403 Blocked

**Check:**
1. `CYBERACCESS_API_KEY` is set and valid
2. CyberAccess backend is running at `CYBERACCESS_API_URL`
3. Subject is not in canary list: `CYBERACCESS_CANARIES=0,999999,canary_admin_vault`

**Fix:**
```bash
# Test direct API call
curl -X POST http://localhost:8000/v1/authorize \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sk_live_your_key_here" \
  -d '{"subject":"alice","resource_id":"item_1","authorized":true}'
```

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                   CODEBASE STRUCTURE                        │
└─────────────────────────────────────────────────────────────┘

bola-frontend/                      (React 19 + Vite)
├── src/
│   ├── App.tsx                    ← Main dashboard
│   ├── lib/api.ts                 ← API client (calls /auth/login, /config, /stats, /risk, /events, /redteam/campaign)
│   └── components/                ← React components
├── Dockerfile                      ← New: for docker-compose compatibility
├── .env                           ← VITE_API_BASE_URL=http://127.0.0.1:8000
└── package.json                   ← npm run dev

bola-benchmark/                    (FastAPI 0.141)
├── app.py                         ← All API endpoints (2700+ lines)
├── test_detector.py               ← 92 tests
├── Dockerfile                     ← Multi-stage build
├── .env                           ← DATABASE_URL, JWT_SECRET, DEMO_PASSWORD, etc.
└── requirements.txt               ← FastAPI, psycopg, scikit-learn, etc.

Lost-foundbyKM/                    (Django)
├── lost_found_project/
│   ├── settings.py               ← CYBERACCESS_* config from env vars (now secure)
│   ├── cyberaccess.py            ← BOLA integration (fixed by side agent)
│   └── urls.py
├── items/views.py                ← Calls enforce_bola()
├── claims/views.py               ← Calls enforce_bola()
├── test_cyberaccess_defense.py   ← Integration tests
├── .env                          ← CYBERACCESS_API_KEY, CYBERACCESS_API_URL
└── .env.example                  ← New: documents all config

docker-compose.yml                (Fixed integration)
├── postgres:5432                 ← Multi-tenant database
├── backend:8000                  ← FastAPI backend (now uses correct service name)
└── frontend:80                   ← Nginx serving React (VITE_API_BASE_URL=http://backend:8000)
```

---

## Status

✅ **Integration Complete**

- Frontend ↔ Backend properly connected
- Lost-foundbyKM security middleware active
- All 6 API endpoints tested and working
- CORS configured for dev/prod
- Docker compose setup fixed
- Environment variables properly documented

**Ready for:**
- Full-stack testing
- Multi-user BOLA scenarios
- Performance benchmarking
- Production deployment (set `APP_ENV=prod` and update env vars)

