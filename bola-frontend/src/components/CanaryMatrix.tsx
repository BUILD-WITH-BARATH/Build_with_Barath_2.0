import React, { useState, useEffect, useCallback } from 'react';

interface CanaryMatrixProps {
  apiBase: string;
  authToken: string;
  currentUserRole: string;
}

export const CanaryMatrix: React.FC<CanaryMatrixProps> = ({
  apiBase,
  authToken,
  currentUserRole
}) => {
  const [canaries, setCanaries] = useState<any[]>([]);
  const [triggers, setTriggers] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [newCanaryId, setNewCanaryId] = useState('');
  const [newCanaryName, setNewCanaryName] = useState('');
  const [isPlanting, setIsPlanting] = useState(false);

  const fetchCanaryData = useCallback(async () => {
    setLoading(true);
    try {
      const [canariesRes, triggersRes] = await Promise.all([
        fetch(`${apiBase}/admin/canaries`, { headers: { Authorization: `Bearer ${authToken}` } }),
        fetch(`${apiBase}/admin/canary-triggers`, { headers: { Authorization: `Bearer ${authToken}` } }),
      ]);
      if (canariesRes.ok) {
        const cData = await canariesRes.json();
        setCanaries(cData.canaries || []);
      }
      if (triggersRes.ok) {
        const tData = await triggersRes.json();
        setTriggers(tData.triggers || []);
      }
    } catch {
      // Fallback
    }
    setLoading(false);
  }, [apiBase, authToken]);

  useEffect(() => {
    fetchCanaryData();
  }, [fetchCanaryData]);

  const handlePlantCanary = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCanaryId.trim() || !newCanaryName.trim()) return;
    setIsPlanting(true);
    try {
      const res = await fetch(`${apiBase}/admin/canaries`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`
        },
        body: JSON.stringify({
          id: newCanaryId.trim(),
          canary_id: newCanaryId.trim(),
          decoy_name: newCanaryName.trim(),
          severity: 'CRITICAL',
          trap_action: 'PERMANENT_BAN'
        })
      });
      if (res.ok) {
        setNewCanaryId('');
        setNewCanaryName('');
        await fetchCanaryData();
      }
    } catch {}
    setIsPlanting(false);
  };

  return (
    <div className="bg-[#171717] rounded-2xl p-5 border border-[#262626] shadow-sm font-sans space-y-5">
      <div className="flex items-center justify-between pb-4 border-b border-[#262626]">
        <div>
          <h2 className="text-sm font-bold tracking-wider text-[#F5F5F5] uppercase flex items-center gap-2 font-mono">
            <span className="text-[#FF3B5C]">🪤</span> CANARY DECOY & FORENSIC TRIP MATRIX
          </h2>
          <p className="text-[11px] text-[#A3A3A3] mt-0.5">
            Active honeypot decoy assets and real-time adversary trigger forensics
          </p>
        </div>
        <button
          onClick={fetchCanaryData}
          disabled={loading}
          className="text-xs font-mono px-3 py-1 bg-[#262626] hover:bg-[#333] text-gray-300 rounded-lg transition-colors"
        >
          {loading ? 'SYNCING...' : 'REFRESH TRAPS'}
        </button>
      </div>

      {/* Active Honeypot Decoys Inventory */}
      <div>
        <h3 className="text-xs font-mono font-bold text-[#A3A3A3] uppercase mb-2">
          PLANTED HONEYPOT ASSETS ({canaries.length})
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {canaries.map((canary) => (
            <div
              key={canary.id}
              className="p-3 bg-[#1C1C1C] border border-[#2B2B2B] rounded-xl flex flex-col justify-between hover:border-[#FF3B5C]/50 transition-colors"
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-white">ID: {canary.id}</span>
                  <span className="text-[9px] font-mono font-bold bg-[#260D12] text-[#FF3B5C] border border-[#FF3B5C]/40 px-1.5 py-0.5 rounded">
                    {canary.severity}
                  </span>
                </div>
                <p className="text-xs text-gray-300 mt-1">{canary.decoy_name}</p>
              </div>
              <div className="mt-3 pt-2 border-t border-[#262626] flex items-center justify-between text-[10px] font-mono text-[#A3A3A3]">
                <span>Action: {canary.trap_action}</span>
                <span>Active 🟢</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Plant New Decoy (Admin Only) */}
      {currentUserRole === 'security_admin' && (
        <form onSubmit={handlePlantCanary} className="p-4 bg-[#141414] border border-[#262626] rounded-xl font-mono text-xs">
          <h4 className="text-xs font-bold text-white uppercase mb-3 flex items-center gap-1.5">
            <span>➕</span> PLANT SYNTHETIC HONEYPOT DECOY
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <input
              type="text"
              placeholder="Decoy ID (e.g. 777777)"
              value={newCanaryId}
              onChange={(e) => setNewCanaryId(e.target.value)}
              className="bg-[#1F1F1F] border border-[#333] rounded-lg px-3 py-2 text-white focus:outline-hidden focus:border-[#FF3B5C]"
            />
            <input
              type="text"
              placeholder="Decoy Name (e.g. VIP Patient Record)"
              value={newCanaryName}
              onChange={(e) => setNewCanaryName(e.target.value)}
              className="bg-[#1F1F1F] border border-[#333] rounded-lg px-3 py-2 text-white focus:outline-hidden focus:border-[#FF3B5C]"
            />
            <button
              type="submit"
              disabled={isPlanting}
              className="bg-[#FF3B5C] hover:bg-[#E02E4D] text-black font-bold py-2 px-4 rounded-lg transition-all disabled:opacity-50"
            >
              {isPlanting ? 'PLANTING...' : 'ARM HONEYPOT'}
            </button>
          </div>
        </form>
      )}

      {/* Forensic Trigger Log */}
      <div>
        <h3 className="text-xs font-mono font-bold text-[#A3A3A3] uppercase mb-2">
          IMMUTABLE CANARY FORENSIC TRIGGERS ({triggers.length})
        </h3>
        {triggers.length === 0 ? (
          <div className="p-4 bg-[#141414] border border-[#262626] rounded-xl text-center text-xs font-mono text-[#A3A3A3]">
            No adversaries have tripped honeypots yet. Traps are silently armed.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#262626] text-[#A3A3A3] text-[10px] uppercase">
                  <th className="py-2 px-3">Timestamp</th>
                  <th className="py-2 px-3">Adversary</th>
                  <th className="py-2 px-3">Tripped Decoy</th>
                  <th className="py-2 px-3">Vector</th>
                  <th className="py-2 px-3">Action Enforced</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#262626]">
                {triggers.map((trig) => (
                  <tr key={trig.id} className="hover:bg-[#1C1C1C] transition-colors">
                    <td className="py-2 px-3 text-[#A3A3A3]">
                      {new Date(trig.triggered_at * 1000).toLocaleTimeString()}
                    </td>
                    <td className="py-2 px-3 font-bold text-[#FF3B5C]">{trig.subject_id}</td>
                    <td className="py-2 px-3 text-white">{trig.canary_id}</td>
                    <td className="py-2 px-3 text-[#F97316]">{trig.endpoint}</td>
                    <td className="py-2 px-3">
                      <span className="bg-[#260D12] text-[#FF3B5C] border border-[#FF3B5C]/40 px-1.5 py-0.5 rounded text-[10px] font-bold">
                        {trig.action_taken}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
