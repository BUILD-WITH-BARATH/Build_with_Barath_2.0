const raw = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
export const API_BASE = raw.startsWith('http') ? raw.replace(/\/$/, '') : `https://${raw}`.replace(/\/$/, '');

const ADMIN_PWD = import.meta.env.VITE_ADMIN_PASSWORD || 'admin_changeme123';

let adminTokenCache: string | null = null;
async function adminToken(): Promise<string> {
  if (adminTokenCache) return adminTokenCache;
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject: 'security_admin', password: ADMIN_PWD }),
  });
  if (!res.ok) throw new Error('admin auth failed');
  const data = await res.json();
  adminTokenCache = data.access_token;
  return adminTokenCache!;
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
  COORDINATED: { scenario_name: 'idor_sweep' },
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
