"""
Phase 4: Advanced threat detection - IP reputation, geo-velocity anomalies,
behavioral baselining, TLS fingerprint blocking.

Design principle: this module is additive. It records its own signals and
can trigger alerts, but it does not alter the core BOLA risk-scoring formula
in app.py's BehavioralRiskEngine, so existing authorization test coverage
stays valid. Callers decide whether/how to act on the signals it returns.

No threat-intelligence data (IP ranges, TLS fingerprints) is hardcoded here:
those require real, continuously-updated feeds and fabricating placeholder
values would be actively misleading. Reputation is instead computed from the
tenant's own observed history, plus optional pluggable external sources the
operator configures with their own credentials.
"""
from __future__ import annotations

import ipaddress
import math
import os
import time
from typing import Optional

import httpx

# ---- Configuration (env-overridable; all features degrade gracefully if disabled/unreachable) ----
THREAT_DETECTION_ENABLED = os.environ.get("THREAT_DETECTION_ENABLED", "true").lower() != "false"

IP_REPUTATION_LOOKBACK_SECONDS = float(os.environ.get("IP_REPUTATION_LOOKBACK_SECONDS", "3600"))
IP_REPUTATION_VIOLATION_THRESHOLD = int(os.environ.get("IP_REPUTATION_VIOLATION_THRESHOLD", "5"))

# Optional: AbuseIPDB (https://www.abuseipdb.com/) - only called if operator supplies their own key.
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL = os.environ.get("ABUSEIPDB_URL", "https://api.abuseipdb.com/api/v2/check")
ABUSEIPDB_TIMEOUT_SECONDS = float(os.environ.get("ABUSEIPDB_TIMEOUT_SECONDS", "2.0"))
ABUSEIPDB_SCORE_THRESHOLD = int(os.environ.get("ABUSEIPDB_SCORE_THRESHOLD", "50"))

# Off by default (like SMTP_ENABLED): this makes a real external network call per lookup,
# so operators opt in explicitly rather than every request silently depending on a third party.
GEO_LOOKUP_ENABLED = os.environ.get("GEO_LOOKUP_ENABLED", "false").lower() == "true"
# ip-api.com's free tier is keyless and HTTP-only; swap via env for a paid/HTTPS provider.
GEO_LOOKUP_URL = os.environ.get("GEO_LOOKUP_URL", "http://ip-api.com/json/{ip}?fields=status,lat,lon,countryCode")
GEO_LOOKUP_TIMEOUT_SECONDS = float(os.environ.get("GEO_LOOKUP_TIMEOUT_SECONDS", "2.0"))
GEO_VELOCITY_MAX_KMH = float(os.environ.get("GEO_VELOCITY_MAX_KMH", "900"))  # ~commercial flight speed
GEO_MIN_INTERVAL_SECONDS = float(os.environ.get("GEO_MIN_INTERVAL_SECONDS", "30"))  # avoid noise on rapid requests

BEHAVIORAL_BASELINE_MIN_SAMPLES = int(os.environ.get("BEHAVIORAL_BASELINE_MIN_SAMPLES", "20"))
BEHAVIORAL_DEVIATION_MULTIPLIER = float(os.environ.get("BEHAVIORAL_DEVIATION_MULTIPLIER", "3.0"))

# Operator-supplied TLS fingerprint blocklist (comma-separated JA3 hashes). Empty by default -
# intentionally not seeded with example values (see module docstring).
TLS_FINGERPRINT_BLOCKLIST = {
    h.strip().lower() for h in os.environ.get("TLS_FINGERPRINT_BLOCKLIST", "").split(",") if h.strip()
}


# ===== IP Reputation =====
def record_ip_event(db, tenant_id: str, ip_address: str, event_type: str, subject_id: Optional[str] = None) -> None:
    """Log an IP-associated event for reputation scoring. event_type: 'denied_auth', 'bola_violation', 'rate_limited', 'request'."""
    if not ip_address:
        return
    try:
        with db() as c:
            c.execute(
                "INSERT INTO threat_ip_events (tenant_id, ip_address, subject_id, event_type, occurred_at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (tenant_id, ip_address, subject_id, event_type, time.time())
            )
    except Exception:
        pass


def internal_ip_reputation(db, tenant_id: str, ip_address: str, now: Optional[float] = None) -> dict:
    """Score an IP purely from this tenant's own recorded history. No external data."""
    now = now or time.time()
    cutoff = now - IP_REPUTATION_LOOKBACK_SECONDS
    try:
        with db() as c:
            rows = c.execute(
                "SELECT event_type, COUNT(*) AS n FROM threat_ip_events "
                "WHERE tenant_id = %s AND ip_address = %s AND occurred_at > %s "
                "GROUP BY event_type",
                (tenant_id, ip_address, cutoff)
            ).fetchall()
    except Exception:
        rows = []

    counts = {r["event_type"]: r["n"] for r in rows}
    violations = counts.get("denied_auth", 0) + counts.get("bola_violation", 0) * 2 + counts.get("rate_limited", 0)

    flagged = violations >= IP_REPUTATION_VIOLATION_THRESHOLD
    return {
        "ip_address": ip_address,
        "violation_score": violations,
        "flagged": flagged,
        "counts": counts,
        "source": "internal",
    }


async def external_ip_reputation(ip_address: str) -> Optional[dict]:
    """Optional AbuseIPDB lookup. Returns None (skipped) unless the operator configured an API key."""
    if not ABUSEIPDB_API_KEY or not ip_address:
        return None
    try:
        async with httpx.AsyncClient(timeout=ABUSEIPDB_TIMEOUT_SECONDS) as client:
            resp = await client.get(
                ABUSEIPDB_URL,
                params={"ipAddress": ip_address, "maxAgeInDays": "90"},
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            )
            if resp.status_code != 200:
                return None
            data = resp.json().get("data", {})
            abuse_score = int(data.get("abuseConfidenceScore", 0))
            return {
                "ip_address": ip_address,
                "abuse_confidence_score": abuse_score,
                "flagged": abuse_score >= ABUSEIPDB_SCORE_THRESHOLD,
                "source": "abuseipdb",
            }
    except Exception:
        return None


# ===== Geo-velocity ("impossible travel") =====
def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0  # Earth radius, km
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def _is_public_ip(ip_address: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_address)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast)
    except ValueError:
        return False  # not even a valid IP (e.g. TestClient's "testclient")


async def geolocate_ip(ip_address: str) -> Optional[dict]:
    """Keyless IP geolocation with graceful degradation. Returns None on any failure/timeout."""
    if not GEO_LOOKUP_ENABLED or not _is_public_ip(ip_address):
        return None
    try:
        async with httpx.AsyncClient(timeout=GEO_LOOKUP_TIMEOUT_SECONDS) as client:
            resp = await client.get(GEO_LOOKUP_URL.format(ip=ip_address))
            return _parse_geo_response(resp)
    except Exception:
        return None


def geolocate_ip_sync(ip_address: str) -> Optional[dict]:
    """Sync counterpart of geolocate_ip, for callers running outside an event loop
    (FastAPI's sync `def` endpoints run in a worker thread with no running loop)."""
    if not GEO_LOOKUP_ENABLED or not _is_public_ip(ip_address):
        return None
    try:
        with httpx.Client(timeout=GEO_LOOKUP_TIMEOUT_SECONDS) as client:
            resp = client.get(GEO_LOOKUP_URL.format(ip=ip_address))
            return _parse_geo_response(resp)
    except Exception:
        return None


def _parse_geo_response(resp: httpx.Response) -> Optional[dict]:
    if resp.status_code != 200:
        return None
    data = resp.json()
    if data.get("status") != "success" or "lat" not in data or "lon" not in data:
        return None
    return {"lat": float(data["lat"]), "lon": float(data["lon"]), "country": data.get("countryCode")}


def check_geo_velocity(db, tenant_id: str, subject_id: str, ip_address: str, location: dict,
                        now: Optional[float] = None) -> dict:
    """Compare a subject's new location against their last known one; flag implausible travel speed."""
    now = now or time.time()
    result = {"flagged": False, "implied_speed_kmh": 0.0, "distance_km": 0.0, "reason": None}

    try:
        with db() as c:
            prev = c.execute(
                "SELECT ip_address, latitude, longitude, observed_at FROM threat_geo_history "
                "WHERE tenant_id = %s AND subject_id = %s",
                (tenant_id, subject_id)
            ).fetchone()

            # Always record the latest known location for next time.
            c.execute(
                "INSERT INTO threat_geo_history (tenant_id, subject_id, ip_address, latitude, longitude, country, observed_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (tenant_id, subject_id) DO UPDATE SET "
                "ip_address = EXCLUDED.ip_address, latitude = EXCLUDED.latitude, longitude = EXCLUDED.longitude, "
                "country = EXCLUDED.country, observed_at = EXCLUDED.observed_at",
                (tenant_id, subject_id, ip_address, location["lat"], location["lon"], location.get("country"), now)
            )
    except Exception:
        return result

    if not prev or prev["ip_address"] == ip_address:
        return result

    elapsed = now - prev["observed_at"]
    if elapsed < GEO_MIN_INTERVAL_SECONDS:
        return result  # too close together to compute a meaningful speed

    distance_km = _haversine_km(prev["latitude"], prev["longitude"], location["lat"], location["lon"])
    elapsed_hours = elapsed / 3600.0
    implied_speed = distance_km / elapsed_hours if elapsed_hours > 0 else float("inf")

    result["distance_km"] = round(distance_km, 1)
    result["implied_speed_kmh"] = round(implied_speed, 1)
    if distance_km > 50 and implied_speed > GEO_VELOCITY_MAX_KMH:
        result["flagged"] = True
        result["reason"] = (
            f"Subject '{subject_id}' moved {distance_km:.0f}km in {elapsed_hours:.2f}h "
            f"(implied {implied_speed:.0f}km/h) - exceeds plausible travel speed"
        )
    return result


# ===== Behavioral baselining =====
def update_behavioral_baseline(db, tenant_id: str, subject_id: str, endpoint: str,
                                now: Optional[float] = None) -> dict:
    """Maintain a per-subject/per-hour-of-day baseline of request pace and flag large deviations.

    The gap since this subject's last request in the same hour-of-day bucket is treated as an
    instantaneous requests-per-minute sample. While the bucket is still warming up (fewer than
    BEHAVIORAL_BASELINE_MIN_SAMPLES observations) samples are averaged in but never flagged, since
    a handful of early requests can't establish what's "normal" yet. Once mature, the baseline
    updates via an exponential moving average (alpha=0.1) so it keeps adapting to gradual change.
    """
    now = now or time.time()
    hour = time.localtime(now).tm_hour
    result = {"flagged": False, "sample_count": 0, "deviation_ratio": 1.0}

    try:
        with db() as c:
            row = c.execute(
                "SELECT avg_requests_per_min, sample_count, updated_at FROM behavioral_profiles "
                "WHERE tenant_id = %s AND subject_id = %s AND hour = %s",
                (tenant_id, subject_id, hour)
            ).fetchone()

            if row is None:
                c.execute(
                    "INSERT INTO behavioral_profiles (tenant_id, subject_id, hour, avg_requests_per_min, "
                    "avg_unique_resources, sample_count, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s) "
                    "ON CONFLICT (tenant_id, subject_id, hour) DO NOTHING",
                    (tenant_id, subject_id, hour, 0, 1, 1, now)
                )
                result["sample_count"] = 1
                return result

            prior_avg = row["avg_requests_per_min"] or 0.0
            sample_count = row["sample_count"] or 0
            delta_seconds = max(now - (row["updated_at"] or now), 0.001)
            instantaneous_rate = 60.0 / delta_seconds
            new_sample_count = sample_count + 1

            if sample_count < BEHAVIORAL_BASELINE_MIN_SAMPLES:
                new_avg = (prior_avg * sample_count + instantaneous_rate) / new_sample_count
                deviation_ratio = instantaneous_rate / max(new_avg, 0.01)
                flagged = False
            else:
                deviation_ratio = instantaneous_rate / max(prior_avg, 0.01)
                flagged = deviation_ratio >= BEHAVIORAL_DEVIATION_MULTIPLIER
                new_avg = prior_avg * 0.9 + instantaneous_rate * 0.1

            c.execute(
                "UPDATE behavioral_profiles SET avg_requests_per_min = %s, sample_count = %s, updated_at = %s "
                "WHERE tenant_id = %s AND subject_id = %s AND hour = %s",
                (new_avg, new_sample_count, now, tenant_id, subject_id, hour)
            )
            result.update({
                "flagged": flagged,
                "sample_count": new_sample_count,
                "deviation_ratio": round(deviation_ratio, 2),
            })
    except Exception:
        return result

    return result


# ===== TLS fingerprint =====
def check_tls_fingerprint(ja3_hash: Optional[str]) -> dict:
    """Check an upstream-supplied JA3 hash against the operator's own blocklist.

    Real JA3 fingerprinting happens at the TLS-terminating layer (load balancer / proxy /
    CDN), not inside this application process - it requires the raw TLS ClientHello, which
    FastAPI/uvicorn never sees once TLS is terminated upstream. This function expects that
    upstream layer to forward the computed hash via a trusted header (e.g. X-JA3-Fingerprint).
    """
    if not ja3_hash:
        return {"flagged": False, "ja3_hash": None}
    normalized = ja3_hash.strip().lower()
    return {
        "flagged": normalized in TLS_FINGERPRINT_BLOCKLIST,
        "ja3_hash": normalized,
    }
