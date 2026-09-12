# Real Data Guide — CyberAccess BOLA Defense

After clearing the fake test data, here's how to populate the system with real data:

---

## Option 1: Real 404 Probes from Lost-foundbyKM

The audit timeline automatically captures **real user behavior**. When actual users trigger 404s on the Lost-foundbyKM portal, they appear in the timeline.

### Setup
1. Clear the fake data (instructions above)
2. Restart services: `docker-compose up --build`
3. Open Lost-foundbyKM: http://localhost:8001

### Real Usage Scenario
Users will naturally trigger 404s as they browse:
```
User clicks broken link → /item/123 (doesn't exist)
   ↓
Middleware detects 404
   ↓
Calls CyberAccess BOLA enforcement
   ↓
Event logged to audit_timeline with real IP/user
   ↓
Dashboard updates in real-time with violet "404 PROBE" badge
```

### What Gets Captured
- **Real IP address** of the user (not test data)
- **Real HTTP verb** (GET, POST, etc.)
- **Real resource being accessed** (item_ID, claim_ID)
- **Real timestamp** of the attempt
- **CyberAccess decision** (allow/deny/block)

---

## Option 2: Programmatic API Calls

Add events by calling the CyberAccess API directly:

### 1. Get Admin Token
```bash
curl -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"subject":"security_admin","password":"admin_changeme123"}'
```

Response:
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer"
}
```

### 2. Trigger Authorization Decisions (Audit Logging)

```bash
TOKEN="<your_token_here>"

# Single authorization check (logs to audit_events)
curl -X POST http://127.0.0.1:8000/v1/authorize \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sk_9zDD4PAGEQMTrLAaAyGuKSsn9h0Fp8seqsNcLIbEtW8" \
  -d '{
    "subject": "alice",
    "resource_id": "item_123",
    "authorized": false,
    "http_verb": "GET"
  }'
```

Response:
```json
{
  "decision": "allow",
  "score": 0,
  "category": "Normal",
  "signals": [],
  "explanations": []
}
```

**This single call automatically:**
- Logs to `audit_events` table
- Broadcasts SSE event in real-time
- Dashboard updates instantly

### 3. View Your Real Data

```bash
# See all audit events (requires admin auth)
curl http://127.0.0.1:8000/audit-timeline?limit=50 \
  -H "Authorization: Bearer $TOKEN"
```

Response shows YOUR real events:
```json
{
  "timeline": [
    {
      "id": 1,
      "timestamp": 1694534400.123,
      "subject": "alice",
      "resource": "item_123",
      "decision": "deny",
      "outcome": "denied",
      "event_type": "denied_access",
      "details": "User not authorized..."
    }
  ],
  "total": 1
}
```

---

## Option 3: Simulate Real Attack Scenarios

Use the dashboard's Live Simulator to generate realistic data:

1. Open http://localhost:5173
2. Go to **LIVE SIMULATOR** section
3. Choose attack type:
   - **NORMAL** — Standard user access patterns
   - **RAPID BOLA** — Enumeration attack (triggers 3-strike lockout)
   - **LOW & SLOW** — Evasive attack patterns
   - **COORDINATED** — Distributed attack

4. Each simulation logs realistic events to the audit timeline

---

## Audit Timeline: What You'll See

After adding real data, the timeline displays:

### Normal User Access
```
🟢 alice → item_123 [NORMAL]
   "User accessed owned resource"
   2 seconds ago
```

### Denied Access (Unauthorized)
```
🟠 bob → claim_456 [DENIED]
   "User not authorized for this resource"
   5 seconds ago
```

### 404 Probe Detected
```
🟣 192.168.1.100 → item_999 [404 PROBE]
   "Object enumeration detected"
   8 seconds ago
```

### Blocked (Attack)
```
🔴 attacker_ip → canary_trap [CANARY]
   "Honeypot triggered - instant lockout"
   12 seconds ago
```

---

## Data Retention

- **In-memory:** Real-time SSE streaming (5 min)
- **Database:** Audit events stored indefinitely in `audit_events` table
- **Export:** Query via `/audit-timeline` endpoint for analysis

---

## Cleanup After Testing

To clear data and start over:

```bash
# Delete Lost-foundbyKM database
rm Lost-foundbyKM/database/db.sqlite3

# Delete PostgreSQL events (if using docker-compose)
docker-compose exec postgres psql -U postgres -d cyberaccess -c 'DELETE FROM audit_events;'

# Restart services
docker-compose down
docker-compose up --build
```

---

## What's Tracked Automatically

Every request to CyberAccess API is logged with:

| Field | Source | Example |
|-------|--------|---------|
| `subject` | From request or client IP | `alice` or `192.168.1.5` |
| `resource_id` | Resource being accessed | `item_123`, `claim_456` |
| `authorized` | Permission status | `true` or `false` |
| `detector_decision` | Risk engine output | `allow`, `deny`, `block` |
| `outcome` | Final action | `allowed`, `denied`, `blocked` |
| `timestamp` | Unix epoch | `1694534400.123` |

---

## Ready to Go!

✅ System is ready for real data  
✅ Audit timeline will auto-populate from your usage  
✅ Dashboard updates in real-time  
✅ All data is secure and isolated by tenant

**Start using Lost-foundbyKM or calling the API — your real events will flow into the Audit Timeline automatically!**
