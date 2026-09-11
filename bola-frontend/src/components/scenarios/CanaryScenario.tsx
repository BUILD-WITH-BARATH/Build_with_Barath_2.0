import { useState } from 'react';
import { registerThrowaway, timedFetch } from '../../lib/demoApi';
import { ScenarioShell, StatusPill } from '../ResultPanel';

// '0' is a seeded honeypot decoy record - looks like a normal low-ID record,
// but any access to it is an instant, permanent ban regardless of any other
// signal. A fresh throwaway account is registered per run so this never
// touches (or bans) a real named demo persona like alice/bob/attacker_1.
const CANARY_RECORD_ID = '0';

interface Result {
  subject: string;
  status: number;
  outcome: string;
  reason: string;
  ms: number;
  bannedNow: boolean;
}

export function CanaryScenario({ apiBase }: { apiBase: string }) {
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Result | null>(null);

  const run = async () => {
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      const { subject, token } = await registerThrowaway(apiBase);
      const r = await timedFetch(apiBase, `/records/${CANARY_RECORD_ID}`, { headers: { Authorization: `Bearer ${token}` } });
      const detail = r.body?.detail ?? r.body;

      // Second request with the same (now-banned) token proves the ban is
      // instant and durable, not just a one-off 403 for this call.
      const r2 = await timedFetch(apiBase, `/records/1`, { headers: { Authorization: `Bearer ${token}` } });
      const bannedNow = r2.status === 403;

      setResult({
        subject,
        status: r.status,
        outcome: r.status === 200 ? 'allowed' : 'denied',
        reason: detail?.reason || 'Honeypot triggered.',
        ms: r.ms,
        bannedNow,
      });
    } catch (e: any) {
      setError(e?.message || 'Demo failed.');
    } finally {
      setRunning(false);
    }
  };

  return (
    <ScenarioShell
      title="4. Honeypot canary trap"
      description={`A fresh throwaway account probes record #${CANARY_RECORD_ID} — a decoy that looks like a normal low-ID record. Touching it at all triggers an instant permanent ban, independent of the risk score.`}
      buttonLabel="▶ RUN (uses a disposable account)"
      running={running}
      onRun={run}
      error={error}
    >
      {result && (
        <div className="flex flex-col gap-2">
          <span className="text-xs font-mono text-[#A3A3A3]">disposable subject: {result.subject}</span>
          <StatusPill status={result.status} outcome={result.outcome} />
          <p className="text-xs text-[#E5E5E5]">{result.reason}</p>
          <span className="text-[10px] font-mono" style={{ color: result.bannedNow ? '#FF3B5C' : '#737373' }}>
            {result.bannedNow
              ? 'confirmed: same token now blocked on an unrelated record too - permanent ban is live'
              : 'follow-up request was not blocked'}
          </span>
          <span className="text-[10px] font-mono text-[#737373]">{result.ms}ms round-trip</span>
        </div>
      )}
    </ScenarioShell>
  );
}
