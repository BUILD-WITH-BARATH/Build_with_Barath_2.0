const raw = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
export const API_BASE = raw.startsWith('http') ? raw.replace(/\/$/, '') : `https://${raw}`.replace(/\/$/, '');

const ADMIN_PWD = import.meta.env.VITE_ADMIN_PASSWORD || 'admin_changeme123';

let adminTokenCache: string | null = null;
let adminTokenInFlight: Promise<string> | null = null;
// Several polling functions (getEvents, getAnalyticsOverview, getThreatSummary,
// getRoiEstimate) all call this on the same ~3s interval. Without de-duping the
// in-flight request, every one of them fires its own /auth/login call whenever
// the cache is empty (e.g. backend still starting up), flooding the browser's
// per-origin connection limit and starving unrelated requests (including the
// login FORM's own fetch) behind the queue.
async function adminToken(): Promise<string> {
  if (adminTokenCache) return adminTokenCache;
  if (!adminTokenInFlight) {
    adminTokenInFlight = (async () => {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject: 'security_admin', password: ADMIN_PWD }),
      });
      if (!res.ok) throw new Error('admin auth failed');
      const data = await res.json();
      adminTokenCache = data.access_token;
      return adminTokenCache!;
    })().finally(() => {
      adminTokenInFlight = null;
    });
  }
  return adminTokenInFlight;
}

export interface ConfigResp {
  short_window: number;
  long_window: number;
  rapid_threshold: number;
  slow_threshold: number;
}

export interface StatsResp {
  active_subjects: number;
  blocked_subjects: number;
  // Backend returns {record_id: distinct_subject_count} for records currently
  // under coordinated attack, not a plain count - the dashboard shows the
  // number of distinct records under coordinated attack (Object.keys length).
  coordinated_attacks: Record<string, number>;
}

export interface RiskResp {
  subject: string;
  score: number;
  category: string;
  signals: string[];
  contributions: Record<string, number>;
  is_blocked: boolean;
  strikes?: number;
  lockout_remaining_s?: number;
  lockout_expires_at?: number;
}

export interface AuditEvent {
  id: number;
  occurred_at: number;
  subject_id: string;
  record_id: string;
  detector_decision: string;
  outcome: string;
  explanation: string;
  event_type?: string;
}

export interface LockoutStatus {
  strike_count: number;
  is_locked: boolean;
  lockout_type?: string;
  lockout_duration_seconds?: number;
  lockout_remaining_seconds: number;
  lockout_expires_at?: number;
  message?: string;
}

// Phase 5: analytics dashboard
export interface AnalyticsOverview {
  tenant_id: string;
  window_hours: number;
  total_events: number;
  outcome_breakdown: Record<string, number>;
  avg_risk_score: number;
  max_risk_score: number;
  unique_subjects_seen: number;
  currently_blocked_subjects: number;
  attacks_blocked: number;
}

// Phase 4: threat detection summary
export interface ThreatSummary {
  tenant_id: string;
  window_hours: number;
  ip_event_breakdown: Record<string, number>;
  flagged_ips: Array<{ ip_address: string; violation_count: number }>;
}

// Phase 5: ROI calculator - see the endpoint's own methodology_note; these are
// operator-configurable assumptions, not verified industry benchmarks.
export interface RoiEstimate {
  tenant_id: string;
  window_days: number;
  methodology_note: string;
  observed: { attacks_blocked: number; requests_denied: number };
  assumptions: {
    cost_per_breach_usd: number;
    breach_probability_per_blocked_attack: number;
    manual_review_minutes_per_event: number;
    engineer_hourly_cost_usd: number;
  };
  estimated_value: {
    breaches_avoided: number;
    breach_cost_avoided_usd: number;
    manual_review_hours_saved: number;
    manual_review_cost_saved_usd: number;
    total_estimated_value_usd: number;
  };
}

export async function getConfig(): Promise<ConfigResp> {
  const res = await fetch(`${API_BASE}/config`);
  if (!res.ok) throw new Error(`config: ${res.status}`);
  return res.json();
}

export async function getStats(): Promise<StatsResp> {
  const res = await fetch(`${API_BASE}/stats`);
  if (!res.ok) throw new Error(`stats: ${res.status}`);
  return res.json();
}

export async function getRisk(subject: string): Promise<RiskResp> {
  const res = await fetch(`${API_BASE}/risk/${encodeURIComponent(subject)}`);
  if (!res.ok) throw new Error(`risk: ${res.status}`);
  return res.json();
}

export async function getLockoutStatus(subject: string): Promise<LockoutStatus> {
  const res = await fetch(`${API_BASE}/lockout-status/${encodeURIComponent(subject)}`);
  if (!res.ok) throw new Error(`lockout: ${res.status}`);
  return res.json();
}

export async function getEvents(): Promise<AuditEvent[]> {
  const token = await adminToken();
  const res = await fetch(`${API_BASE}/audit-timeline?limit=50`, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error(`events: ${res.status}`);
  const data = await res.json();
  return (data.timeline || []).map((e: any) => ({
    id: e.id,
    occurred_at: e.timestamp,
    subject_id: e.subject,
    record_id: e.resource,
    detector_decision: e.decision,
    outcome: e.outcome,
    explanation: e.details,
    event_type: e.event_type,
  }));
}

export interface SignupResult {
  tenant_id: string;
  name: string;
  api_key: string;
  warning: string;
}

export async function signup(name: string, email?: string): Promise<SignupResult> {
  const res = await fetch(`${API_BASE}/v1/signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(email ? { name, email } : { name }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Signup failed (${res.status})`);
  }
  return res.json();
}

export async function getAnalyticsOverview(tenantId = 'demo', windowHours = 24): Promise<AnalyticsOverview> {
  const token = await adminToken();
  const res = await fetch(`${API_BASE}/tenants/${encodeURIComponent(tenantId)}/analytics/overview?window_hours=${windowHours}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`analytics overview: ${res.status}`);
  return res.json();
}

export async function getThreatSummary(tenantId = 'demo', windowHours = 24): Promise<ThreatSummary> {
  const token = await adminToken();
  const res = await fetch(`${API_BASE}/tenants/${encodeURIComponent(tenantId)}/analytics/threat-summary?window_hours=${windowHours}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`threat summary: ${res.status}`);
  return res.json();
}

export async function getRoiEstimate(tenantId = 'demo', windowDays = 30): Promise<RoiEstimate> {
  const token = await adminToken();
  const res = await fetch(`${API_BASE}/tenants/${encodeURIComponent(tenantId)}/analytics/roi?window_days=${windowDays}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`roi estimate: ${res.status}`);
  return res.json();
}

export interface SimResult {
  scenario: string;
  attacker_subject: string;
  total_requests: number;
  blocked_count: number;
  denied_count: number;
  allowed_count: number;
  interception_rate_percent: number;
  peak_risk_score: number;
  verdict: string;
}

// idor_sweep/horizontal_privilege/stealth_creep are safe, repeatable presets -
// none touch canary IDs (0, 999999, canary_admin_vault), so none risk a real
// permanent ban on a named demo persona. NORMAL isn't a backend preset - it
// passes bob's own record IDs explicitly so the campaign runner scores a
// legitimate, fully-authorized access pattern instead of an attack. Uses bob,
// not alice: the horizontal_privilege preset below hardcodes alice as its
// attacker, and running it earns her a real (if short) strike lockout - using
// her again for the "NORMAL" baseline would then show a false denial.
const SCENARIOS: Record<string, { scenario_name?: string; attacker_subject?: string; target_records?: string[] }> = {
  NORMAL: { attacker_subject: 'bob', target_records: ['51', '52', '53'] },
  'RAPID BOLA': { scenario_name: 'horizontal_privilege' },
  'LOW & SLOW': { scenario_name: 'stealth_creep' },
  'COORDINATED': { scenario_name: 'idor_sweep' },
};

export async function runSimulation(kind: keyof typeof SCENARIOS): Promise<SimResult> {
  const payload = SCENARIOS[kind];
  const res = await fetch(`${API_BASE}/redteam/campaign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`campaign: ${res.status}`);
  return res.json();
}

export { SCENARIOS };
