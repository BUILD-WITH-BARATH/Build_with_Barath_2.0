import { useState } from 'react';
import { login, timedFetch } from '../../lib/demoApi';
import { ScenarioShell, StatusPill } from '../ResultPanel';

const RECORD_ID = '1';

interface Result {
  actor: string;
  status: number;
  outcome: string;
  reason: string;
  score: number;
  ms: number;
}

export function OwnershipScenario({ apiBase }: { apiBase: string }) {
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ownerResult, setOwnerResult] = useState<Result | null>(null);
  const [attackerResult, setAttackerResult] = useState<Result | null>(null);

  const run = async () => {
    setRunning(true);
    setError(null);
    setOwnerResult(null);
    setAttackerResult(null);
    try {
      const ownerToken = await login(apiBase, 'alice');
      const r1 = await timedFetch(apiBase, `/records/${RECORD_ID}`, { headers: { Authorization: `Bearer ${ownerToken}` } });
      setOwnerResult({
        actor: 'alice (owner)',
        status: r1.status,
        outcome: r1.status === 200 ? 'allowed' : 'denied',
        reason: r1.body?.decision?.explanations?.[0] || 'Access allowed: ownership verified.',
        score: r1.body?.score ?? 0,
        ms: r1.ms,
      });

      const attackerToken = await login(apiBase, 'attacker_1');
      const r2 = await timedFetch(apiBase, `/records/${RECORD_ID}`, { headers: { Authorization: `Bearer ${attackerToken}` } });
      const detail = r2.body?.detail ?? r2.body;
      setAttackerResult({
        actor: 'attacker_1 (no relation)',
        status: r2.status,
        outcome: r2.status === 200 ? 'allowed' : 'denied',
        reason: detail?.reason || detail?.explanations?.[0] || 'Access denied.',
        score: detail?.score ?? 0,
        ms: r2.ms,
      });
    } catch (e: any) {
      setError(e?.message || 'Demo failed.');
    } finally {
      setRunning(false);
    }
  };

  return (
    <ScenarioShell
      title="1. Ownership check"
      description={`Two different accounts request the exact same record (GET /records/${RECORD_ID}). One owns it, one doesn't.`}
      buttonLabel="▶ RUN"
      running={running}
      onRun={run}
      error={error}
    >
      <div className="flex flex-col md:flex-row gap-4">
        {[ownerResult, attackerResult].map((r, i) => (
          <div key={i} className="flex-1 min-w-[220px]">
            {!r && <div className="text-xs text-[#525252] font-mono">{running ? 'waiting...' : 'not run yet'}</div>}
            {r && (
              <div className="flex flex-col gap-2">
                <span className="text-xs font-mono text-[#A3A3A3]">{r.actor}</span>
                <StatusPill status={r.status} outcome={r.outcome} />
                <p className="text-xs text-[#E5E5E5]">{r.reason}</p>
                <span className="text-[10px] font-mono text-[#737373]">score: {r.score} · {r.ms}ms</span>
              </div>
            )}
          </div>
        ))}
      </div>
    </ScenarioShell>
  );
}
