import React, { useState, useEffect, useCallback } from 'react';

interface AbacExplorerProps {
  apiBase: string;
  authToken: string;
}

export const AbacExplorer: React.FC<AbacExplorerProps> = ({ apiBase, authToken }) => {
  const [recordId, setRecordId] = useState('1');
  const [clearance, setClearance] = useState(0);
  const [simulatedHour, setSimulatedHour] = useState(14); // 2 PM
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchAbac = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(
        `${apiBase}/records/${encodeURIComponent(recordId)}/abac?clearance=${clearance}&hour=${simulatedHour}`,
        {
          headers: { Authorization: `Bearer ${authToken}` }
        }
      );
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.detail?.reason || 'ABAC access denied');
        setResult(null);
      } else {
        setResult(data);
        setError(null);
      }
    } catch (err: any) {
      setError(err.message || 'Error querying ABAC endpoint');
    }
    setLoading(false);
  }, [apiBase, authToken, recordId, clearance, simulatedHour]);

  useEffect(() => {
    fetchAbac();
  }, [fetchAbac]);

  return (
    <div className="bg-[#171717] rounded-2xl p-5 border border-[#262626] shadow-sm font-sans">
      <div className="flex items-center justify-between pb-4 border-b border-[#262626]">
        <div>
          <h2 className="text-sm font-bold tracking-wider text-[#F5F5F5] uppercase flex items-center gap-2 font-mono">
            <span className="text-emerald-400">🛡️</span> DYNAMIC ABAC & FIELD-LEVEL REDACTION EXPLORER
          </h2>
          <p className="text-[11px] text-[#A3A3A3] mt-0.5">
            Test how security clearance, operational hours, and classification dynamically mask sensitive fields
          </p>
        </div>
        <span className="text-[10px] font-mono bg-emerald-950/60 text-emerald-400 border border-emerald-500/40 px-2.5 py-1 rounded-full uppercase tracking-wider">
          POLICY ENGINE ACTIVE
        </span>
      </div>

      {/* Control Filters */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 py-4 border-b border-[#262626] font-mono text-xs">
        <div>
          <label className="text-[10px] text-[#A3A3A3] uppercase block mb-1">Target Record ID</label>
          <input
            type="text"
            value={recordId}
            onChange={(e) => setRecordId(e.target.value)}
            className="w-full bg-[#1F1F1F] border border-[#333] rounded-lg px-3 py-2 text-white focus:outline-hidden focus:border-[#FF3B5C]"
          />
          <div className="flex flex-wrap gap-1 mt-1.5">
            <button
              type="button"
              onClick={() => setRecordId('1')}
              className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[#262626] hover:bg-[#333] text-gray-300 transition-colors"
            >
              #1 Alice
            </button>
            <button
              type="button"
              onClick={() => setRecordId('8')}
              className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[#262626] hover:bg-[#333] text-gray-300 transition-colors"
            >
              #8 Ward A
            </button>
            <button
              type="button"
              onClick={() => setRecordId('17')}
              className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[#262626] hover:bg-[#333] text-gray-300 transition-colors"
            >
              #17 Support
            </button>
            <button
              type="button"
              onClick={() => setRecordId('55')}
              className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[#262626] hover:bg-[#333] text-gray-300 transition-colors"
            >
              #55 Bob
            </button>
          </div>
        </div>
        <div>
          <label className="text-[10px] text-[#A3A3A3] uppercase block mb-1">Operator Clearance (0 to 5)</label>
          <input
            type="range"
            min="0"
            max="5"
            value={clearance}
            onChange={(e) => setClearance(Number(e.target.value))}
            className="w-full accent-emerald-400 cursor-pointer"
          />
          <div className="flex justify-between text-[10px] text-[#A3A3A3] mt-1">
            <span>Level 0 (Public)</span>
            <span className="text-emerald-400 font-bold">Level {clearance}</span>
            <span>Level 5 (Top Secret)</span>
          </div>
        </div>
        <div>
          <label className="text-[10px] text-[#A3A3A3] uppercase block mb-1">Simulated Hour (0-23h)</label>
          <input
            type="range"
            min="0"
            max="23"
            value={simulatedHour}
            onChange={(e) => setSimulatedHour(Number(e.target.value))}
            className="w-full accent-cyan-400 cursor-pointer"
          />
          <div className="flex justify-between text-[10px] text-[#A3A3A3] mt-1">
            <span>00:00 (Night)</span>
            <span className="text-cyan-400 font-bold">{simulatedHour}:00</span>
            <span>23:00</span>
          </div>
        </div>
      </div>

      {/* Policy Evaluation Output */}
      <div className="py-4">
        {loading && (
          <p className="text-xs font-mono text-[#A3A3A3] animate-pulse">Evaluating dynamic ABAC policy conditions...</p>
        )}

        {error && (
          <div className="p-3 rounded-xl bg-[#201013] border border-[#DC2626]/40 text-[#FF3B5C] font-mono text-xs">
            <strong>ABAC POLICY DENIAL:</strong> {error}
          </div>
        )}

        {result && (
          <div className="space-y-3 font-mono text-xs">
            <div className="flex items-center gap-3">
              <span className="text-[10px] bg-[#262626] text-gray-300 px-2.5 py-1 rounded">
                Classification: <strong className="text-white">{result.record?.classification || 'standard'}</strong>
              </span>
              <span className="text-[10px] bg-[#262626] text-gray-300 px-2.5 py-1 rounded">
                Redacted Fields: <strong className="text-[#FF3B5C]">{result.redacted_fields?.length || 0}</strong>
              </span>
            </div>

            <div className="bg-[#0D0D0D] border border-[#262626] p-4 rounded-xl">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] uppercase tracking-wider text-[#A3A3A3]">Dynamically Filtered Record Payload</span>
                {result.redacted_fields?.length > 0 ? (
                  <span className="text-[10px] text-[#FF3B5C] font-bold">FIELDS MASKED</span>
                ) : (
                  <span className="text-[10px] text-emerald-400 font-bold">FULL CLINICAL VISIBILITY</span>
                )}
              </div>
              <pre className="text-[#E5E5E5] text-[11px] overflow-x-auto">
                {JSON.stringify(result.record, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
