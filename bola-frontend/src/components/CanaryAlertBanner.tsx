import React from 'react';

interface CanaryAlertBannerProps {
  alert: {
    alert_id?: string;
    threat_type?: string;
    attacker_identity?: string;
    targeted_record_id?: string;
    risk_score?: number;
    strike_level?: string;
    mitigation_action?: string;
    timestamp?: number;
  } | null;
  onDismiss: () => void;
}

export const CanaryAlertBanner: React.FC<CanaryAlertBannerProps> = ({ alert, onDismiss }) => {
  if (!alert) return null;

  const isCanary = alert.threat_type?.includes('CANARY') || (alert.risk_score ?? 0) >= 100;

  return (
    <div className="w-full bg-[#200A0F] border-b border-[#FF3B5C]/60 text-white px-6 py-3.5 shadow-lg flex items-center justify-between animate-pulse">
      <div className="flex items-center gap-4">
        <div className="w-10 h-10 rounded-full bg-[#FF3B5C]/20 border border-[#FF3B5C] flex items-center justify-center shrink-0">
          <span className="text-xl">🚨</span>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="bg-[#FF3B5C] text-black font-mono font-black text-[10px] uppercase px-2 py-0.5 rounded tracking-wider">
              {isCanary ? 'CRITICAL HONEYPOT TRIP' : 'CRITICAL SOC INCIDENT'}
            </span>
            <span className="text-xs font-mono text-[#A3A3A3]">
              {alert.alert_id || 'SOC-INCIDENT'}
            </span>
            <span className="text-xs font-mono text-[#FF3B5C] font-bold">
              {alert.strike_level || 'Strike 3/3'}
            </span>
          </div>
          <p className="text-sm font-sans text-gray-200 mt-1">
            Attacker <strong className="text-white font-mono bg-black/40 px-1.5 py-0.5 rounded">{alert.attacker_identity || 'adversary'}</strong> probed decoy record{' '}
            <strong className="text-[#FF3B5C] font-mono">{alert.targeted_record_id || 'honeypot'}</strong>. Action Enforced:{' '}
            <span className="text-emerald-400 font-mono font-bold">{alert.mitigation_action || 'PERMANENT_IDENTITY_BLACKLIST'}</span>.
          </p>
        </div>
      </div>
      <div className="flex items-center gap-3">
        <button
          onClick={onDismiss}
          className="text-xs font-mono px-3 py-1 rounded bg-[#FF3B5C]/20 hover:bg-[#FF3B5C]/30 text-[#FF3B5C] border border-[#FF3B5C]/50 transition-colors"
        >
          ACKNOWLEDGE
        </button>
      </div>
    </div>
  );
};
