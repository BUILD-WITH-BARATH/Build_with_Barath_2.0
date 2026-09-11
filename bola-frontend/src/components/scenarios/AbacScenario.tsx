import { useState } from 'react';
import { login, ADMIN_PWD, timedFetch } from '../../lib/demoApi';
import { ScenarioShell } from '../ResultPanel';

const RECORD_ID = '1';

interface Result {
  actor: string;
  fields: Record<string, any>;
  redactedFields: string[];
}

function FieldRow({ name, value, redacted }: { name: string; value: any; redacted: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 py-1 border-b border-[#1f1f1f] last:border-0">
      <span className="text-xs font-mono text-[#737373]">{name}</span>
      <span
        className="text-xs font-mono"
        style={{ color: redacted ? '#FF3B5C' : '#E5E5E5' }}
      >
        {typeof value === 'string' ? value : JSON.stringify(value)}
      </span>
    </div>
  );
}

export function AbacScenario({ apiBase }: { apiBase: string }) {
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [doctorResult, setDoctorResult] = useState<Result | null>(null);
  const [adminResult, setAdminResult] = useState<Result | null>(null);

  const run = async () => {
    setRunning(true);
    setError(null);
    setDoctorResult(null);
    setAdminResult(null);
    try {
      const doctorToken = await login(apiBase, 'dr_singh');
      const r1 = await timedFetch(apiBase, `/records/${RECORD_ID}/abac`, { headers: { Authorization: `Bearer ${doctorToken}` } });
      setDoctorResult({
        actor: 'dr_singh (role: doctor, assigned to this record)',
        fields: r1.body?.record?.data || {},
        redactedFields: r1.body?.redacted_fields || [],
      });

      const adminToken = await login(apiBase, 'security_admin', ADMIN_PWD);
      const r2 = await timedFetch(apiBase, `/records/${RECORD_ID}/abac`, { headers: { Authorization: `Bearer ${adminToken}` } });
      setAdminResult({
        actor: 'security_admin (elevated clearance)',
        fields: r2.body?.record?.data || {},
        redactedFields: r2.body?.redacted_fields || [],
      });
    } catch (e: any) {
      setError(e?.message || 'Demo failed.');
    } finally {
      setRunning(false);
    }
  };

  return (
    <ScenarioShell
      title="3. Dynamic ABAC + field redaction"
      description="Same record, two roles. Sensitive fields (psychiatric notes, SSN) are masked per-field based on role and clearance — not an all-or-nothing document access decision."
      buttonLabel="▶ RUN"
      running={running}
      onRun={run}
      error={error}
    >
      <div className="flex flex-col md:flex-row gap-4">
        {[doctorResult, adminResult].map((r, i) => (
          <div key={i} className="flex-1 min-w-[240px] rounded-xl border border-[#262626] p-3">
            {!r && <div className="text-xs text-[#525252] font-mono">{running ? 'waiting...' : 'not run yet'}</div>}
            {r && (
              <div className="flex flex-col gap-1">
                <span className="text-xs font-mono text-[#A3A3A3] mb-1">{r.actor}</span>
                {Object.entries(r.fields).map(([k, v]) => (
                  <FieldRow key={k} name={k} value={v} redacted={r.redactedFields.includes(k)} />
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </ScenarioShell>
  );
}
