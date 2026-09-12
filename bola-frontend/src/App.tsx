import { useEffect, useRef, useState } from 'react';
import {
  getConfig, getStats, getRisk, getEvents, runSimulation, SCENARIOS,
  type ConfigResp, type StatsResp, type RiskResp, type AuditEvent,
} from './lib/api';

const SIM_BUTTONS: Array<{ key: keyof typeof SCENARIOS; classes: string }> = [
  { key: 'NORMAL', classes: 'bg-[#171717] hover:bg-[#202020] text-[#F5F5F5] border border-[#262626]' },
  { key: 'RAPID BOLA', classes: 'bg-[#1c0e11] hover:bg-[#261217] border border-[#FF3B5C] text-[#FF3B5C]' },
  { key: 'LOW & SLOW', classes: 'bg-[#1c120a] hover:bg-[#26170d] border border-[#F97316] text-[#F97316]' },
  { key: 'COORDINATED', classes: 'bg-[#1b0d0e] hover:bg-[#251214] border border-[#DC2626] text-[#DC2626]' },
];

function timeAgo(unixSeconds: number): string {
  const diff = Math.max(0, Date.now() / 1000 - unixSeconds);
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  return `${Math.round(diff / 3600)}h ago`;
}

function App() {
  const [online, setOnline] = useState<boolean | null>(null);
  const [config, setConfig] = useState<ConfigResp | null>(null);
  const [stats, setStats] = useState<StatsResp | null>(null);
  const [riskSubject, setRiskSubject] = useState('');
  const [risk, setRisk] = useState<RiskResp | null>(null);
  const [riskLoading, setRiskLoading] = useState(false);
  const [simRunning, setSimRunning] = useState<string | null>(null);
  const [simVerdict, setSimVerdict] = useState<string | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const refreshPassive = async () => {
    try {
      const [c, s] = await Promise.all([getConfig(), getStats()]);
      setConfig(c);
      setStats(s);
      setOnline(true);
    } catch {
      setOnline(false);
    }
    try {
      setEvents(await getEvents());
    } catch {
      // audit timeline needs security_admin auth; leave prior state on failure
    }
  };

  useEffect(() => {
    refreshPassive();
    const timer = setInterval(refreshPassive, 6000);
    return () => clearInterval(timer);
  }, []);

  const fetchRisk = async (subject: string) => {
    if (!subject.trim()) {
      setRisk(null);
      return;
    }
    setRiskLoading(true);
    try {
      setRisk(await getRisk(subject.trim()));
    } catch {
      setRisk(null);
    } finally {
      setRiskLoading(false);
    }
  };

  const onSubjectInput = (value: string) => {
    setRiskSubject(value);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => fetchRisk(value), 500);
  };

  const runSim = async (kind: keyof typeof SCENARIOS) => {
    setSimRunning(kind);
    setSimVerdict(null);
    try {
      const result = await runSimulation(kind);
      setSimVerdict(`${result.verdict} (${result.interception_rate_percent}% intercepted, peak risk ${result.peak_risk_score})`);
      setRiskSubject(result.attacker_subject);
      await fetchRisk(result.attacker_subject);
      await refreshPassive();
    } catch {
      setSimVerdict('Simulation failed - backend unreachable.');
    } finally {
      setSimRunning(null);
    }
  };

  const resetDemo = () => {
    setRiskSubject('');
    setRisk(null);
    setSimVerdict(null);
    refreshPassive();
  };

  const shortWindowLabel = config ? `${config.short_window}s` : '...';
  const longWindowLabel = config ? `${config.long_window}s` : '...';
  const shortThresholdLabel = config ? `Threshold: ${config.rapid_threshold} uniq` : 'Threshold: - uniq';
  const longThresholdLabel = config ? `Threshold: ${config.slow_threshold} uniq` : 'Threshold: - uniq';

  return (
    <div className="bg-[#0A0A0A] text-[#F5F5F5] min-h-screen flex flex-col">
      {/* BEGIN: MainHeader */}
      <header className="bg-[#111111] text-[#F5F5F5] px-6 py-3.5 flex items-center justify-between shadow-sm border-b border-[#262626] relative after:absolute after:bottom-0 after:left-0 after:right-0 after:h-[1px] after:bg-gradient-to-r after:from-[#FF3B5C]/0 after:via-[#FF3B5C]/60 after:to-[#FF3B5C]/0">
        <div className="flex items-center space-x-3.5">
          <div className="flex items-center justify-center shrink-0">
            <img
              src="https://lh3.googleusercontent.com/aida-public/AB6AXuCNrNyR3WSUtFfGM6VrgbwEx5W3YT4wDBMwvdIctuRJj3_Smrnc5mN0xz7jGvWLkEYjVwKtGjJbIExISJuoxJKbcEtA6yDlhTcvIGy54TJL-sZeRAxY2CqSUUTRtHELarLG7hX3y2mXHkvDzhC8Dcr_cY56anYHRnCMsJIWHUyA03HX56YKQ5iG9CDSEssFrL3-T8d1GwaccYQ9TeHVdO1flp_NhmTuwB8ZZ0dqcgZnFBbllDXkUj0a"
              alt="Futuristic Crimson Cyber Shield Emblem"
              className="block object-contain drop-shadow-[0_0_12px_rgba(255,59,92,0.3)]"
              style={{ width: 56, height: 56, mixBlendMode: 'screen', filter: 'brightness(1.2) contrast(1.1)' }}
            />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-wider leading-none text-[#FF3B5C] font-sans">INTEGRITY</h1>
            <p className="text-[10px] font-mono tracking-widest text-[#A3A3A3] uppercase mt-1">DETERMINISTIC AUTH + BEHAVIORAL DEFENSE</p>
          </div>
        </div>
        <div>
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#171717] border border-[#262626] text-[#A3A3A3] text-xs font-mono tracking-wide shadow-xs">
            <svg
              className="w-3.5 h-3.5"
              style={{ color: online === false ? '#FF3B5C' : '#22D3A6' }}
              fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"
            >
              <path d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 011.06 0z" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <span className="text-[#F5F5F5]">{online === null ? 'CHECKING...' : online ? 'ONLINE' : 'OFFLINE'}</span>
          </div>
        </div>
      </header>
      {/* END: MainHeader */}

      {/* BEGIN: MainContentGrid */}
      <main className="flex-1 max-w-[1720px] w-full mx-auto p-5 grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* BEGIN: LeftColumn */}
        <div className="lg:col-span-4 flex flex-col gap-5">
          {/* Card: Security Overview */}
          <section className="bg-[#171717] rounded-2xl p-5 border border-[#262626] shadow-sm" data-purpose="security-overview-card">
            <div className="flex items-center gap-2 mb-4">
              <svg className="w-4 h-4 text-[#FF3B5C]" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24">
                <path d="M2.25 18L9 11.25l4.306 4.307a11.95 11.95 0 015.814-5.519l2.74-1.22m0 0l-5.94-2.28m5.94 2.28l-2.28 5.941" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              <h2 className="text-xs font-bold tracking-wider text-[#F5F5F5] uppercase font-sans">SECURITY OVERVIEW</h2>
            </div>
            <div className="grid grid-cols-2 gap-3 mb-3">
              <div className="bg-[#171717] border border-[#262626] rounded-xl p-3.5 flex flex-col justify-between shadow-xs hover:border-[#3a3a3a] transition-colors">
                <span className="text-2xl font-bold text-[#F5F5F5] leading-none">{stats?.active_subjects ?? 0}</span>
                <span className="text-[10px] font-bold text-[#A3A3A3] uppercase tracking-wide mt-3">ACTIVE SUBJECTS</span>
              </div>
              <div className="bg-[#201013] border border-[#DC2626]/40 rounded-xl p-3.5 flex flex-col justify-between shadow-xs hover:border-[#FF3B5C]/60 transition-colors">
                <span className="text-2xl font-bold text-[#FF3B5C] leading-none">{stats?.blocked_subjects ?? 0}</span>
                <span className="text-[10px] font-bold text-[#DC2626] uppercase tracking-wide mt-3">BLOCKED SUBJECTS</span>
              </div>
            </div>
            <div className="bg-[#22140c] border border-[#F97316]/40 rounded-xl p-3.5 flex flex-col justify-between shadow-xs hover:border-[#F97316]/70 transition-colors">
              <span className="text-2xl font-bold text-[#F97316] leading-none">{stats ? Object.keys(stats.coordinated_attacks).length : 0}</span>
              <span className="text-[10px] font-bold text-[#F97316] uppercase tracking-wide mt-3">COORDINATED ATTACKS DETECTED</span>
            </div>
          </section>

          {/* Card: System Config */}
          <section className="bg-[#171717] rounded-2xl p-5 border border-[#262626] shadow-sm" data-purpose="system-config-card">
            <div className="flex items-center gap-2 mb-4">
              <svg className="w-4 h-4 text-[#FF3B5C]" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24">
                <path d="M6.429 9.75L2.25 12l4.179 2.25m0-4.5l5.571 3 5.571-3m-11.142 0L2.25 7.5 12 2.25l9.75 5.25-4.179 2.25m0 0L21.75 12l-4.179 2.25m0 0l4.179 2.25L12 21.75 2.25 16.5l4.179-2.25m11.142 0l-5.571 3-5.571-3" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              <h2 className="text-xs font-bold tracking-wider text-[#F5F5F5] uppercase font-sans">SYSTEM CONFIG</h2>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <span className="block text-[10px] font-bold text-[#A3A3A3] uppercase tracking-wide mb-1.5">SHORT WINDOW</span>
                <div className="bg-[#0A0A0A] border border-[#262626] rounded-xl py-2 px-3 flex items-center gap-2">
                  <svg className="w-3.5 h-3.5 text-[#FF3B5C]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <path d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  <span className="text-xs font-semibold text-[#F5F5F5]">{shortWindowLabel}</span>
                </div>
                <span className="block text-[10px] text-[#737373] mt-1 font-mono">{shortThresholdLabel}</span>
              </div>
              <div>
                <span className="block text-[10px] font-bold text-[#A3A3A3] uppercase tracking-wide mb-1.5">LONG WINDOW</span>
                <div className="bg-[#0A0A0A] border border-[#262626] rounded-xl py-2 px-3 flex items-center gap-2">
                  <svg className="w-3.5 h-3.5 text-[#F97316]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <path d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  <span className="text-xs font-semibold text-[#F5F5F5]">{longWindowLabel}</span>
                </div>
                <span className="block text-[10px] text-[#737373] mt-1 font-mono">{longThresholdLabel}</span>
              </div>
            </div>
          </section>
        </div>
        {/* END: LeftColumn */}

        {/* BEGIN: CenterColumn */}
        <div className="lg:col-span-4 flex flex-col gap-5">
          {/* Card: Live Risk Monitor */}
          <section className="bg-[#171717] rounded-2xl p-5 border border-[#262626] shadow-sm" data-purpose="live-risk-monitor-card">
            <div className="flex items-center justify-between gap-2 mb-4">
              <div className="flex items-center gap-2">
                <svg className="w-4 h-4 text-[#FF3B5C]" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24">
                  <path d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                <h2 className="text-xs font-bold tracking-wider text-[#F5F5F5] uppercase font-sans">LIVE RISK MONITOR</h2>
              </div>
              <div className="relative w-40">
                <input
                  className="w-full bg-[#0A0A0A] border border-[#262626] text-[#F5F5F5] placeholder-[#737373] text-xs rounded-lg py-1 px-2.5 focus:outline-none focus:ring-1 focus:ring-[#FF3B5C] focus:border-[#FF3B5C] transition-colors"
                  placeholder="Type a subject ID..."
                  type="text"
                  value={riskSubject}
                  onChange={(e) => onSubjectInput(e.target.value)}
                />
              </div>
            </div>
            <div className="bg-[#0A0A0A] border border-[#262626] rounded-xl p-5 flex items-center justify-between mb-5 shadow-xs">
              <div className="text-5xl font-extrabold text-[#FF3B5C] tracking-tight drop-shadow-[0_0_12px_rgba(255,59,92,0.3)]">
                {riskLoading ? '...' : risk?.score ?? 0}
              </div>
              <div className="flex flex-col items-end">
                <span className="text-[10px] font-bold text-[#A3A3A3] uppercase tracking-wide mb-1">STATUS</span>
                <span className="bg-[#171717] border border-[#262626] text-[#F5F5F5] text-xs font-bold px-2.5 py-0.5 rounded uppercase tracking-wide">
                  {risk?.category ?? 'NORMAL'}
                </span>
              </div>
            </div>
            <div className="pt-1">
              <span className="text-[10px] font-bold text-[#A3A3A3] uppercase tracking-wide">SCORE BREAKDOWN</span>
              <div className="flex flex-col gap-1 mt-2">
                {risk && Object.keys(risk.contributions).length > 0 ? (
                  Object.entries(risk.contributions).map(([signal, val]) => (
                    <div key={signal} className="flex items-center justify-between text-[11px] font-mono">
                      <span className="text-[#A3A3A3]">{signal}</span>
                      <span className="text-[#F5F5F5]">+{val}</span>
                    </div>
                  ))
                ) : (
                  <span className="text-[11px] font-mono text-[#525252]">
                    {riskSubject ? 'no signals for this subject' : 'type a subject ID above'}
                  </span>
                )}
              </div>
            </div>
          </section>

          {/* Card: Live Simulator */}
          <section className="bg-[#171717] rounded-2xl p-5 border border-[#262626] shadow-sm" data-purpose="live-simulator-card">
            <div className="flex items-center gap-2 mb-4">
              <svg className="w-4 h-4 text-[#FF3B5C]" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24">
                <path d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              <h2 className="text-xs font-bold tracking-wider text-[#F5F5F5] uppercase font-sans">LIVE SIMULATOR</h2>
            </div>
            <div className="grid grid-cols-2 gap-3 mb-4">
              {SIM_BUTTONS.map((btn) => (
                <button
                  key={btn.key}
                  onClick={() => runSim(btn.key)}
                  disabled={simRunning !== null}
                  className={`${btn.classes} font-bold text-xs py-3 px-4 rounded-xl shadow-xs transition-colors tracking-wide disabled:opacity-50 disabled:cursor-not-allowed`}
                >
                  {simRunning === btn.key ? 'RUNNING...' : btn.key}
                </button>
              ))}
            </div>
            {simVerdict && (
              <p className="text-[11px] font-mono text-[#A3A3A3] text-center mb-2 leading-relaxed">{simVerdict}</p>
            )}
            <div className="flex justify-center pt-2">
              <button
                onClick={resetDemo}
                className="inline-flex items-center justify-center gap-2 bg-[#171717] hover:bg-[#222222] border border-[#262626] text-[#F5F5F5] font-bold text-xs py-2 px-5 rounded-xl shadow-xs hover:shadow-sm transition-all"
              >
                <svg className="w-3.5 h-3.5 text-[#A3A3A3]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                <span>RESET DEMO</span>
              </button>
            </div>
          </section>
        </div>
        {/* END: CenterColumn */}

        {/* BEGIN: RightColumn */}
        <div className="lg:col-span-4 flex flex-col h-full">
          {/* Card: Audit Timeline */}
          <section className="bg-[#171717] rounded-2xl p-5 border border-[#262626] shadow-sm h-[550px] flex flex-col" data-purpose="audit-timeline-card">
            <div className="flex items-center gap-2 mb-4">
              <svg className="w-4 h-4 text-[#FF3B5C]" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24">
                <path d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 5.625c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              <h2 className="text-xs font-bold tracking-wider text-[#F5F5F5] uppercase font-sans">AUDIT TIMELINE</h2>
            </div>
            {events.length === 0 ? (
              <div className="flex-1 flex items-center justify-center py-20">
                <p className="text-xs font-mono text-[#737373] tracking-wide">No events recorded.</p>
              </div>
            ) : (
              <div className="flex-1 overflow-y-auto flex flex-col gap-2 pr-1">
                {events.map((ev) => (
                  <div key={ev.id} className="bg-[#0A0A0A] border border-[#262626] rounded-xl p-3 flex flex-col gap-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-[#F5F5F5]">{ev.subject_id}</span>
                      <span
                        className="text-[10px] font-bold uppercase px-2 py-0.5 rounded"
                        style={{
                          color: ev.outcome === 'allowed' ? '#22D3A6' : '#FF3B5C',
                          backgroundColor: ev.outcome === 'allowed' ? '#052e22' : '#2a0e14',
                        }}
                      >
                        {ev.outcome}
                      </span>
                    </div>
                    <span className="text-[10px] font-mono text-[#737373]">
                      record #{ev.record_id} · {timeAgo(ev.occurred_at)}
                    </span>
                    {ev.explanation?.[0] && (
                      <span className="text-[11px] text-[#A3A3A3] leading-snug">{ev.explanation[0]}</span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
        {/* END: RightColumn */}
      </main>
      {/* END: MainContentGrid */}
    </div>
  );
}

export default App;
