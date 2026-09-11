import { useState } from 'react';
import { login, timedFetch } from '../../lib/demoApi';
import { ScenarioShell } from '../ResultPanel';

// alice owns 1-50, bob owns 51-100 - mix ids alice owns with ids she doesn't.
// NOTE: never include '0', '999999', or 'canary_admin_vault' here - those are
// registered honeypot canary records and fetching one as alice would trigger
// a real PERMANENT_BAN on her account, breaking every other demo scenario.
const BATCH_IDS = ['1', '2', '51', '52', '9999'];

interface BatchItem {
  record_id: string;
  status: string;
  score?: number;
}

export function BatchScenario({ apiBase }: { apiBase: string }) {
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [items, setItems] = useState<BatchItem[] | null>(null);
  const [summary, setSummary] = useState<{ allowed: number; denied: number; blocked: number } | null>(null);

  const run = async () => {
    setRunning(true);
    setError(null);
    setItems(null);
    setSummary(null);
    try {
      const token = await login(apiBase, 'alice');
      const r = await timedFetch(apiBase, '/records/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ record_ids: BATCH_IDS, action: 'read' }),
      });
      setItems(r.body.results || []);
      setSummary({ allowed: r.body.allowed ?? 0, denied: r.body.denied ?? 0, blocked: r.body.blocked ?? 0 });
    } catch (e: any) {
      setError(e?.message || 'Demo failed.');
    } finally {
      setRunning(false);
    }
  };

  return (
    <ScenarioShell
      title="2. Batch / bulk request"
      description={`alice sends one batch request for ${BATCH_IDS.length} record IDs — some hers, some bob's, one nonexistent. Each ID is authorized independently, not the whole batch as one unit.`}
      buttonLabel="▶ RUN"
      running={running}
      onRun={run}
      error={error}
    >
      {items && (
        <div className="flex flex-col gap-2">
          <div className="flex gap-4 text-xs font-mono text-[#A3A3A3] mb-1">
            <span className="text-[#22D3A6]">{summary?.allowed} allowed</span>
            <span className="text-[#FF3B5C]">{summary?.denied} denied</span>
            <span className="text-[#F97316]">{summary?.blocked} blocked</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {items.map((it) => (
              <span
                key={it.record_id}
                className="px-2.5 py-1 rounded-lg font-mono text-[11px]"
                style={{
                  backgroundColor: it.status === 'allowed' ? '#052e22' : '#2a0e14',
                  color: it.status === 'allowed' ? '#22D3A6' : '#FF3B5C',
                  border: `1px solid ${it.status === 'allowed' ? '#22D3A680' : '#FF3B5C80'}`,
                }}
              >
                #{it.record_id} {it.status}
              </span>
            ))}
          </div>
        </div>
      )}
    </ScenarioShell>
  );
}
