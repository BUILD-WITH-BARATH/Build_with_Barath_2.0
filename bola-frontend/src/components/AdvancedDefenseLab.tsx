import React, { useState } from 'react';

interface AdvancedDefenseLabProps {
  apiBase: string;
  authToken: string;
  onRefreshTelemetry: () => void;
}

export const AdvancedDefenseLab: React.FC<AdvancedDefenseLabProps> = ({
  apiBase,
  authToken,
  onRefreshTelemetry
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'mutation' | 'hierarchy' | 'body' | 'batch' | 'async' | 'graphql' | 'stored' | 'canary'>('mutation');
  const [loading, setLoading] = useState(false);
  const [labResult, setLabResult] = useState<any>(null);

  // Mutation state
  const [mutationVerb, setMutationVerb] = useState<'PUT' | 'PATCH' | 'DELETE'>('DELETE');
  const [mutationRecordId, setMutationRecordId] = useState('1');
  const [mutationPayload, setMutationPayload] = useState('{"data": "malicious_overwrite_attempt"}');

  // Hierarchy state
  const [hierarchyMode, setHierarchyMode] = useState<'valid' | 'broken'>('broken');

  // Body payload state
  const [bodyTargetId, setBodyTargetId] = useState('55');

  // Batch state
  const [batchIds, setBatchIds] = useState('1, 2, 55, 56, 99');

  // Async job state
  const [asyncRecordId, setAsyncRecordId] = useState('1');

  // GraphQL query state
  const [gqlRecordId, setGqlRecordId] = useState('55');

  // Stored ref state
  const [storedTargetId, setStoredTargetId] = useState('1');

  const executeMutation = async () => {
    setLoading(true);
    setLabResult(null);
    try {
      let bodyData: any = undefined;
      if (mutationVerb !== 'DELETE') {
        try { bodyData = JSON.parse(mutationPayload); } catch { bodyData = { data: mutationPayload }; }
      }
      const res = await fetch(`${apiBase}/records/${encodeURIComponent(mutationRecordId)}`, {
        method: mutationVerb,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`
        },
        body: bodyData ? JSON.stringify(bodyData) : undefined
      });
      const data = await res.json().catch(() => ({}));
      setLabResult({
        endpoint: `${mutationVerb} /records/${mutationRecordId}`,
        status: res.status,
        headers: {
          decision: res.headers.get('X-Detector-Decision'),
          signals: res.headers.get('X-Detector-Signals'),
          score: res.headers.get('X-Risk-Score')
        },
        body: data
      });
      onRefreshTelemetry();
    } catch (err: any) {
      setLabResult({ error: err.message });
    }
    setLoading(false);
  };

  const executeHierarchy = async () => {
    setLoading(true);
    setLabResult(null);
    try {
      const chain = hierarchyMode === 'valid'
        ? [
            { type: 'organization', id: 'org_demo' },
            { type: 'department', id: 'dept_cardiology' },
            { type: 'record', id: '1' }
          ]
        : [
            { type: 'organization', id: 'org_demo' },
            { type: 'department', id: 'dept_rival_oncology' }, // Mismatched ancestor parent
            { type: 'record', id: '1' }
          ];

      const res = await fetch(`${apiBase}/hierarchy/access`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`
        },
        body: JSON.stringify({ chain, action: 'read' })
      });
      const data = await res.json().catch(() => ({}));
      setLabResult({
        endpoint: 'POST /hierarchy/access',
        status: res.status,
        headers: {
          decision: res.headers.get('X-Detector-Decision'),
          score: res.headers.get('X-Risk-Score')
        },
        body: data
      });
      onRefreshTelemetry();
    } catch (err: any) {
      setLabResult({ error: err.message });
    }
    setLoading(false);
  };

  const executeBodyPayload = async () => {
    setLoading(true);
    setLabResult(null);
    try {
      const res = await fetch(`${apiBase}/hierarchy/nodes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`
        },
        body: JSON.stringify({
          resource_type: 'report',
          resource_id: 'rep_probe_' + Date.now().toString().slice(-4),
          parent_type: 'record',
          foreign_target_id: bodyTargetId
        })
      });
      const data = await res.json().catch(() => ({}));
      setLabResult({
        endpoint: 'POST /hierarchy/nodes (intercepted by BodyObjectReferenceMiddleware)',
        status: res.status,
        body: data,
        note: `Scanned body for ID keys, detected reference to unowned record '${bodyTargetId}', and flagged risk score automatically.`
      });
      onRefreshTelemetry();
    } catch (err: any) {
      setLabResult({ error: err.message });
    }
    setLoading(false);
  };

  const executeBatch = async () => {
    setLoading(true);
    setLabResult(null);
    try {
      const ids = batchIds.split(',').map(s => s.trim()).filter(Boolean);
      const res = await fetch(`${apiBase}/records/batch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`
        },
        body: JSON.stringify({ record_ids: ids, action: 'read' })
      });
      const data = await res.json().catch(() => ({}));
      setLabResult({
        endpoint: 'POST /records/batch',
        status: res.status,
        body: data
      });
      onRefreshTelemetry();
    } catch (err: any) {
      setLabResult({ error: err.message });
    }
    setLoading(false);
  };

  const executeAsyncJob = async () => {
    setLoading(true);
    setLabResult(null);
    try {
      const createRes = await fetch(`${apiBase}/jobs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`
        },
        body: JSON.stringify({ resource_id: asyncRecordId, action: 'export_vitals' })
      });
      const createData = await createRes.json();
      if (!createRes.ok) {
        setLabResult({ endpoint: 'POST /jobs', status: createRes.status, body: createData });
        setLoading(false);
        return;
      }

      // Execute worker
      const execRes = await fetch(`${apiBase}/jobs/${createData.job_id}/execute`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${authToken}` }
      });
      const execData = await execRes.json().catch(() => ({}));

      setLabResult({
        endpoint: `POST /jobs/${createData.job_id}/execute`,
        status: execRes.status,
        body: {
          enqueued_job: createData,
          worker_execution: execData
        }
      });
      onRefreshTelemetry();
    } catch (err: any) {
      setLabResult({ error: err.message });
    }
    setLoading(false);
  };

  const executeGraphQL = async () => {
    setLoading(true);
    setLabResult(null);
    try {
      const query = `query { record(id: "${gqlRecordId}") { id ownerId data } }`;
      const res = await fetch(`${apiBase}/graphql`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`
        },
        body: JSON.stringify({ query })
      });
      const data = await res.json().catch(() => ({}));
      setLabResult({
        endpoint: 'POST /graphql (Strawberry AST Hook)',
        status: res.status,
        body: data
      });
      onRefreshTelemetry();
    } catch (err: any) {
      setLabResult({ error: err.message });
    }
    setLoading(false);
  };

  const executeStoredRef = async () => {
    setLoading(true);
    setLabResult(null);
    try {
      const createRes = await fetch(`${apiBase}/stored-references`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`
        },
        body: JSON.stringify({ ref_type: 'webhook', target_resource_id: storedTargetId })
      });
      const createData = await createRes.json();
      if (!createRes.ok) {
        setLabResult({ endpoint: 'POST /stored-references', status: createRes.status, body: createData });
        setLoading(false);
        return;
      }

      // Trigger revalidation
      const trigRes = await fetch(`${apiBase}/stored-references/${createData.ref_id}/trigger`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${authToken}` }
      });
      const trigData = await trigRes.json().catch(() => ({}));

      setLabResult({
        endpoint: `POST /stored-references/${createData.ref_id}/trigger`,
        status: trigRes.status,
        body: {
          created_reference: createData,
          consumption_revalidation: trigData
        }
      });
      onRefreshTelemetry();
    } catch (err: any) {
      setLabResult({ error: err.message });
    }
    setLoading(false);
  };

  const executeCanaryTrip = async () => {
    setLoading(true);
    setLabResult(null);
    try {
      const res = await fetch(`${apiBase}/records/999999`, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      const data = await res.json().catch(() => ({}));
      setLabResult({
        endpoint: 'GET /records/999999 (CRITICAL HONEYPOT DECOY)',
        status: res.status,
        body: data,
        alert: '🚨 ATTACKER IDENTIFIED & TRAPPED: Permanent 10-Year Firewall Ban Applied Immediately.'
      });
      onRefreshTelemetry();
    } catch (err: any) {
      setLabResult({ error: err.message });
    }
    setLoading(false);
  };

  return (
    <div className="bg-[#171717] rounded-2xl p-5 border border-[#262626] shadow-sm font-sans">
      <div className="flex items-center justify-between pb-4 border-b border-[#262626]">
        <div>
          <h2 className="text-sm font-bold tracking-wider text-[#F5F5F5] uppercase flex items-center gap-2 font-mono">
            <span className="text-[#FF3B5C]">⚔️</span> ADVANCED BOLA DEFENSE LAB
          </h2>
          <p className="text-[11px] text-[#A3A3A3] mt-0.5">
            Test and trigger all 9 defense modules against live backend endpoints
          </p>
        </div>
        <span className="text-[10px] font-mono bg-[#221316] text-[#FF3B5C] border border-[#FF3B5C]/30 px-2.5 py-1 rounded-full uppercase tracking-wider">
          9 DEFENSE VECTORS ACTIVE
        </span>
      </div>

      {/* Sub-tab Pills */}
      <div className="flex items-center gap-1.5 overflow-x-auto py-3 border-b border-[#262626] scrollbar-none text-xs font-mono">
        {[
          { id: 'mutation', label: '1. Mutation BOLA', icon: '✏️' },
          { id: 'hierarchy', label: '2. Hierarchy Chain', icon: '🌲' },
          { id: 'body', label: '3. Body ID Scanner', icon: '📦' },
          { id: 'batch', label: '4. Batch Array', icon: '📑' },
          { id: 'async', label: '5. Async Queue', icon: '⏳' },
          { id: 'graphql', label: '6. GraphQL AST', icon: '🕸️' },
          { id: 'stored', label: '7. Stored BOLA', icon: '💾' },
          { id: 'canary', label: '9. Honeypot Trap', icon: '🪤' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveSubTab(tab.id as any)}
            className={`px-3 py-1.5 rounded-lg whitespace-nowrap transition-all flex items-center gap-1.5 ${
              activeSubTab === tab.id
                ? 'bg-[#FF3B5C] text-black font-bold shadow-xs'
                : 'bg-[#1E1E1E] text-[#A3A3A3] hover:text-white hover:bg-[#282828]'
            }`}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Active Panel Content */}
      <div className="py-4">
        {activeSubTab === 'mutation' && (
          <div className="space-y-4">
            <p className="text-xs text-[#A3A3A3]">
              Enforces HTTP verb-weighted risk scoring. Unauthorized <code className="text-[#FF3B5C]">DELETE</code> triggers a 3x weight (75 risk points), while <code className="text-[#F97316]">PUT</code>/<code className="text-[#F97316]">PATCH</code> trigger 2x weight.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div>
                <label className="text-[10px] font-mono text-[#A3A3A3] uppercase block mb-1">HTTP Verb</label>
                <select
                  value={mutationVerb}
                  onChange={(e: any) => setMutationVerb(e.target.value)}
                  className="w-full bg-[#1F1F1F] border border-[#333] rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-hidden focus:border-[#FF3B5C]"
                >
                  <option value="DELETE">DELETE (Weight 3.0x - Critical)</option>
                  <option value="PUT">PUT (Weight 2.0x - High)</option>
                  <option value="PATCH">PATCH (Weight 2.5x - High)</option>
                </select>
              </div>
              <div>
                <label className="text-[10px] font-mono text-[#A3A3A3] uppercase block mb-1">Target Record ID</label>
                <input
                  type="text"
                  value={mutationRecordId}
                  onChange={(e) => setMutationRecordId(e.target.value)}
                  className="w-full bg-[#1F1F1F] border border-[#333] rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-hidden focus:border-[#FF3B5C]"
                  placeholder="Record ID (e.g. 1)"
                />
              </div>
              <div className="flex items-end">
                <button
                  onClick={executeMutation}
                  disabled={loading}
                  className="w-full py-2 px-4 rounded-lg bg-[#FF3B5C] hover:bg-[#E02E4D] text-black font-mono font-bold text-xs transition-all disabled:opacity-50"
                >
                  {loading ? 'DISPATCHING...' : `EXECUTE ${mutationVerb} MUTATION`}
                </button>
              </div>
            </div>
            {mutationVerb !== 'DELETE' && (
              <div>
                <label className="text-[10px] font-mono text-[#A3A3A3] uppercase block mb-1">Payload JSON</label>
                <input
                  type="text"
                  value={mutationPayload}
                  onChange={(e) => setMutationPayload(e.target.value)}
                  className="w-full bg-[#1F1F1F] border border-[#333] rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-hidden focus:border-[#FF3B5C]"
                  placeholder='{"data": "updated_content"}'
                />
              </div>
            )}
          </div>
        )}

        {activeSubTab === 'hierarchy' && (
          <div className="space-y-4">
            <p className="text-xs text-[#A3A3A3]">
              Recursively validates relational parent-child links (<code className="text-emerald-400">Org → Dept → Record</code>). Prevents attackers from referencing records across invalid organizational branches.
            </p>
            <div className="flex items-center gap-4">
              <label className="flex items-center gap-2 text-xs font-mono text-white cursor-pointer">
                <input
                  type="radio"
                  name="hierarchy_mode"
                  checked={hierarchyMode === 'broken'}
                  onChange={() => setHierarchyMode('broken')}
                  className="accent-[#FF3B5C]"
                />
                <span className="text-[#FF3B5C] font-bold">Tampered Ancestor Chain (BOLA Traversal Attempt)</span>
              </label>
              <label className="flex items-center gap-2 text-xs font-mono text-white cursor-pointer">
                <input
                  type="radio"
                  name="hierarchy_mode"
                  checked={hierarchyMode === 'valid'}
                  onChange={() => setHierarchyMode('valid')}
                  className="accent-emerald-400"
                />
                <span className="text-emerald-400">Valid Ancestor Chain</span>
              </label>
            </div>
            <button
              onClick={executeHierarchy}
              disabled={loading}
              className="py-2 px-4 rounded-lg bg-[#FF3B5C] hover:bg-[#E02E4D] text-black font-mono font-bold text-xs transition-all disabled:opacity-50"
            >
              {loading ? 'VALIDATING...' : 'TEST HIERARCHICAL ACCESS'}
            </button>
          </div>
        )}

        {activeSubTab === 'body' && (
          <div className="space-y-4">
            <p className="text-xs text-[#A3A3A3]">
              Intercepts JSON body payloads via ASGI middleware, recursively identifies object identifier patterns, and flags unowned foreign references before application handlers process them.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] font-mono text-[#A3A3A3] uppercase block mb-1">Foreign Object ID in Body</label>
                <input
                  type="text"
                  value={bodyTargetId}
                  onChange={(e) => setBodyTargetId(e.target.value)}
                  className="w-full bg-[#1F1F1F] border border-[#333] rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-hidden focus:border-[#FF3B5C]"
                />
              </div>
              <div className="flex items-end">
                <button
                  onClick={executeBodyPayload}
                  disabled={loading}
                  className="w-full py-2 px-4 rounded-lg bg-[#FF3B5C] hover:bg-[#E02E4D] text-black font-mono font-bold text-xs transition-all disabled:opacity-50"
                >
                  {loading ? 'SCANNING...' : 'INJECT FOREIGN ID IN JSON BODY'}
                </button>
              </div>
            </div>
          </div>
        )}

        {activeSubTab === 'batch' && (
          <div className="space-y-4">
            <p className="text-xs text-[#A3A3A3]">
              Processes bulk multi-ID arrays with atomic batch size caps and mid-batch strike escalation. If an attacker injects foreign IDs, remaining items in the array are blocked immediately.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] font-mono text-[#A3A3A3] uppercase block mb-1">Comma-separated Record IDs</label>
                <input
                  type="text"
                  value={batchIds}
                  onChange={(e) => setBatchIds(e.target.value)}
                  className="w-full bg-[#1F1F1F] border border-[#333] rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-hidden focus:border-[#FF3B5C]"
                />
              </div>
              <div className="flex items-end">
                <button
                  onClick={executeBatch}
                  disabled={loading}
                  className="w-full py-2 px-4 rounded-lg bg-[#FF3B5C] hover:bg-[#E02E4D] text-black font-mono font-bold text-xs transition-all disabled:opacity-50"
                >
                  {loading ? 'EVALUATING...' : 'EXECUTE BATCH EVALUATION'}
                </button>
              </div>
            </div>
          </div>
        )}

        {activeSubTab === 'async' && (
          <div className="space-y-4">
            <p className="text-xs text-[#A3A3A3]">
              Generates cryptographic HMAC pre-authorization proof tokens at enqueue time and verifies them prior to background worker execution to prevent asynchronous privilege escalation.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] font-mono text-[#A3A3A3] uppercase block mb-1">Target Resource ID</label>
                <input
                  type="text"
                  value={asyncRecordId}
                  onChange={(e) => setAsyncRecordId(e.target.value)}
                  className="w-full bg-[#1F1F1F] border border-[#333] rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-hidden focus:border-[#FF3B5C]"
                />
              </div>
              <div className="flex items-end">
                <button
                  onClick={executeAsyncJob}
                  disabled={loading}
                  className="w-full py-2 px-4 rounded-lg bg-[#FF3B5C] hover:bg-[#E02E4D] text-black font-mono font-bold text-xs transition-all disabled:opacity-50"
                >
                  {loading ? 'PROCESSING...' : 'ENQUEUE & RUN ASYNC WORKER'}
                </button>
              </div>
            </div>
          </div>
        )}

        {activeSubTab === 'graphql' && (
          <div className="space-y-4">
            <p className="text-xs text-[#A3A3A3]">
              Executes GraphQL query via Strawberry AST resolver hooks at <code className="text-cyan-400">/graphql</code>. Evaluates object permissions and honeypot traps on graph traversal nodes.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] font-mono text-[#A3A3A3] uppercase block mb-1">GraphQL Record Query ID</label>
                <input
                  type="text"
                  value={gqlRecordId}
                  onChange={(e) => setGqlRecordId(e.target.value)}
                  className="w-full bg-[#1F1F1F] border border-[#333] rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-hidden focus:border-[#FF3B5C]"
                />
              </div>
              <div className="flex items-end">
                <button
                  onClick={executeGraphQL}
                  disabled={loading}
                  className="w-full py-2 px-4 rounded-lg bg-[#FF3B5C] hover:bg-[#E02E4D] text-black font-mono font-bold text-xs transition-all disabled:opacity-50"
                >
                  {loading ? 'QUERYING...' : 'EXECUTE GRAPHQL QUERY'}
                </button>
              </div>
            </div>
          </div>
        )}

        {activeSubTab === 'stored' && (
          <div className="space-y-4">
            <p className="text-xs text-[#A3A3A3]">
              Dual-phase second-order BOLA validation. Enforces authorization when storing webhook/resource pointers, and re-verifies object authorization dynamically at trigger time.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] font-mono text-[#A3A3A3] uppercase block mb-1">Target Resource ID</label>
                <input
                  type="text"
                  value={storedTargetId}
                  onChange={(e) => setStoredTargetId(e.target.value)}
                  className="w-full bg-[#1F1F1F] border border-[#333] rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-hidden focus:border-[#FF3B5C]"
                />
              </div>
              <div className="flex items-end">
                <button
                  onClick={executeStoredRef}
                  disabled={loading}
                  className="w-full py-2 px-4 rounded-lg bg-[#FF3B5C] hover:bg-[#E02E4D] text-black font-mono font-bold text-xs transition-all disabled:opacity-50"
                >
                  {loading ? 'STORE & TRIGGER...' : 'TEST STORED REFERENCE'}
                </button>
              </div>
            </div>
          </div>
        )}

        {activeSubTab === 'canary' && (
          <div className="space-y-4">
            <div className="p-3 bg-[#240C12] border border-[#FF3B5C]/40 rounded-xl">
              <h4 className="text-xs font-bold text-[#FF3B5C] uppercase font-mono flex items-center gap-2">
                <span>⚠️</span> ACTIVE DECOY HONEYPOT TRIP
              </h4>
              <p className="text-xs text-gray-300 mt-1">
                Accessing decoy ID <code className="text-[#FF3B5C] font-bold">999999</code> or <code className="text-[#FF3B5C] font-bold">canary_admin_vault</code> triggers an instant permanent ban, skips progressive warning lockouts, and generates forensic forensic audit records.
              </p>
            </div>
            <button
              onClick={executeCanaryTrip}
              disabled={loading}
              className="w-full py-2.5 px-4 rounded-lg bg-[#FF3B5C] hover:bg-[#E02E4D] text-black font-mono font-black text-xs uppercase tracking-wider transition-all shadow-lg shadow-[#FF3B5C]/20 disabled:opacity-50"
            >
              {loading ? 'TRIPPING HONEYPOT...' : 'PROBE HONEYPOT TRAP (ID 999999)'}
            </button>
          </div>
        )}
      </div>

      {/* Lab Result Display */}
      {labResult && (
        <div className="mt-4 pt-4 border-t border-[#262626] font-mono text-xs">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] uppercase tracking-wider text-[#A3A3A3]">LIVE EXECUTION TELEMETRY</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
              labResult.status === 200 ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/40' : 'bg-[#201013] text-[#FF3B5C] border border-[#DC2626]/40'
            }`}>
              STATUS {labResult.status || 'FAILED'}
            </span>
          </div>
          {labResult.alert && (
            <div className="p-2.5 bg-[#FF3B5C]/20 border border-[#FF3B5C] text-[#FF3B5C] rounded-lg mb-2 font-bold">
              {labResult.alert}
            </div>
          )}
          <pre className="bg-[#0D0D0D] border border-[#262626] p-3 rounded-xl overflow-x-auto text-[#E5E5E5] text-[11px] max-h-56">
            {JSON.stringify(labResult, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};
