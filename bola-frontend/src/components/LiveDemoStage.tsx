import { useState } from 'react';
import { DEMO_PWD } from '../LoginView';

interface DemoResult {
  actor: string;
  recordId: string;
  status: number;
  outcome: 'allowed' | 'denied' | 'error';
  reason: string;
  score?: number;
  raw: any;
  ms: number;
}

const VICTIM = 'alice';
const ATTACKER = 'attacker_1';
const TARGET_RECORD_ID = '1'; // alice's own record - owned by VICTIM, not ATTACKER

async function login(apiBase: string, subject: string): Promise<string> {
  const res = await fetch(`${apiBase}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject, password: DEMO_PWD }),
  });
  if (!res.ok) throw new Error(`login failed for ${subject}: ${res.status}`);
  const data = await res.json();
  return data.access_token as string;
}

async function fetchRecordAs(apiBase: string, actorLabel: string, token: string, recordId: string): Promise<DemoResult> {
  const start = performance.now();
  const res = await fetch(`${apiBase}/records/${recordId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const ms = Math.round(performance.now() - start);
  const body = await res.json().catch(() => ({}));
  if (res.ok) {
    return {
      actor: actorLabel,
      recordId,
      status: res.status,
      outcome: 'allowed',
      reason: body?.decision?.explanations?.[0] || 'Access allowed: ownership verified.',
      score: body?.score ?? 0,
      raw: body,
      ms,
    };
  }
  const detail = body?.detail ?? body;
  return {
    actor: actorLabel,
    recordId,
    status: res.status,
    outcome: 'denied',
    reason: detail?.reason || detail?.explanations?.[0] || detail?.detail || 'Access denied.',
    score: detail?.score ?? 0,
    raw: body,
    ms,
  };
}

function ResultCard({ result, loading, label, tone }: { result: DemoResult | null; loading: boolean; label: string; tone: 'victim' | 'attacker' }) {
  const accent = tone === 'victim' ? '#22D3A6' : '#FF3B5C';
  return (
    <div
      className="flex-1 min-w-[260px] rounded-2xl border p-5 bg-[#141414] transition-all"
      style={{ borderColor: result ? accent + '80' : '#262626' }}
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-mono uppercase tracking-wider text-[#A3A3A3]">{label}</span>
        {loading && (
          <span className="text-[10px] font-mono text-[#F97316] animate-pulse">CALLING BACKEND...</span>
        )}
      </div>

      {!result && !loading && (
        <div className="text-sm text-[#525252] font-mono py-6 text-center">Press "Run Live Demo" below</div>
      )}

      {result && (
        <div className="flex flex-col gap-3">
          <div
            className="inline-flex self-start items-center gap-2 px-3 py-1.5 rounded-full font-mono text-xs font-bold"
            style={{
              backgroundColor: result.outcome === 'allowed' ? '#052e22' : '#2a0e14',
              color: result.outcome === 'allowed' ? '#22D3A6' : '#FF3B5C',
              border: `1px solid ${result.outcome === 'allowed' ? '#22D3A680' : '#FF3B5C80'}`,
            }}
          >
            HTTP {result.status} · {result.outcome.toUpperCase()}
          </div>
          <p className="text-sm text-[#E5E5E5] leading-snug">{result.reason}</p>
          <div className="flex items-center gap-4 text-[11px] font-mono text-[#737373]">
            <span>risk score: <b style={{ color: accent }}>{result.score}</b></span>
            <span>{result.ms}ms round-trip</span>
            <span>record #{result.recordId}</span>
          </div>
        </div>
      )}
    </div>
  );
}

export function LiveDemoStage({ apiBase }: { apiBase: string }) {
  const [running, setRunning] = useState(false);
  const [victimResult, setVictimResult] = useState<DemoResult | null>(null);
  const [attackerResult, setAttackerResult] = useState<DemoResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runDemo = async () => {
    setRunning(true);
    setError(null);
    setVictimResult(null);
    setAttackerResult(null);
    try {
      const [victimToken, attackerToken] = await Promise.all([
        login(apiBase, VICTIM),
        login(apiBase, ATTACKER),
      ]);

      const victimRes = await fetchRecordAs(apiBase, `${VICTIM} (owner)`, victimToken, TARGET_RECORD_ID);
      setVictimResult(victimRes);

      const attackerRes = await fetchRecordAs(apiBase, `${ATTACKER} (no relation to record)`, attackerToken, TARGET_RECORD_ID);
      setAttackerResult(attackerRes);
    } catch (e: any) {
      setError(e?.message || 'Demo failed - check backend is reachable.');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <section className="rounded-2xl border border-[#262626] bg-gradient-to-br from-[#171717] to-[#0d0d0d] p-7">
        <h1 className="text-xl font-bold text-[#F5F5F5] mb-2">Live BOLA Defense Demo</h1>
        <p className="text-sm text-[#A3A3A3] max-w-2xl leading-relaxed">
          One button. Two live requests against the real backend, same record,
          same API. One caller owns it, one doesn't. Watch the API make the
          call in real time — no mocked data, no canned response.
        </p>

        <button
          onClick={runDemo}
          disabled={running}
          className="mt-5 inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-[#FF3B5C] text-black font-bold font-mono text-sm tracking-wide hover:bg-[#ff5470] active:scale-95 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {running ? 'RUNNING LIVE REQUESTS...' : '▶ RUN LIVE DEMO'}
        </button>

        {error && (
          <p className="mt-3 text-sm text-[#FF3B5C] font-mono">{error}</p>
        )}
      </section>

      <div className="flex flex-col md:flex-row gap-5">
        <ResultCard result={victimResult} loading={running && !victimResult} label={`Owner requests own record`} tone="victim" />
        <ResultCard result={attackerResult} loading={running && !!victimResult && !attackerResult} label={`Attacker requests same record`} tone="attacker" />
      </div>

      <section className="rounded-2xl border border-[#262626] bg-[#141414] p-5">
        <h2 className="text-xs font-bold tracking-wider text-[#F5F5F5] uppercase mb-2">What just happened</h2>
        <p className="text-sm text-[#A3A3A3] leading-relaxed">
          Both requests hit the exact same endpoint (<code className="text-[#F5F5F5]">GET /records/{TARGET_RECORD_ID}</code>)
          on the real backend. The API checked object-level ownership per request — not a role
          check, not a URL-pattern check — and an unsupervised ML model scored the attacker's
          access pattern as anomalous. This is the BOLA/IDOR class of bug (OWASP API1:2023):
          most APIs only check "is this user authenticated," never "does this user actually own
          this specific object."
        </p>
      </section>
    </div>
  );
}
