import { useState, useEffect, useCallback } from 'react';

const rawApiBase = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
const API_BASE = rawApiBase.startsWith('http') ? rawApiBase.replace(/\/$/, '') : `https://${rawApiBase}`.replace(/\/$/, '');

export default function App() {
  const [stats, setStats] = useState<any>(null);
  const [config, setConfig] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [riskData, setRiskData] = useState<any>(null);
  const [selectedSubject, setSelectedSubject] = useState('alice');
  const [subjectInput, setSubjectInput] = useState('');
  const [isOnline, setIsOnline] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [authToken, setAuthToken] = useState<string | null>(null);

  useEffect(() => {
    const autoLogin = async () => {
      try {
        const res = await fetch(`${API_BASE}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ subject: 'security_admin', password: 'admin_changeme123' })
        });
        if (res.ok) {
          const data = await res.json();
          setAuthToken(data.access_token);
        } else {
          const demoRes = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ subject: 'alice', password: 'changeme123' })
          });
          if (demoRes.ok) {
            const demoData = await demoRes.json();
            setAuthToken(demoData.access_token);
          }
        }
      } catch {
        // Backend offline
      }
    };
    autoLogin();
  }, []);

  const fetchData = useCallback(async (subjOverride?: string) => {
    const subj = subjOverride !== undefined ? subjOverride : (selectedSubject || 'alice');
    try {
      const headers: Record<string, string> = authToken ? { Authorization: `Bearer ${authToken}` } : {};
      const [statsRes, configRes, riskRes, eventsRes] = await Promise.all([
        fetch(`${API_BASE}/stats`),
        fetch(`${API_BASE}/config`),
        fetch(`${API_BASE}/risk/${encodeURIComponent(subj)}`),
        authToken
          ? fetch(`${API_BASE}/audit-events`, { headers })
          : fetch(`${API_BASE}/events`, { headers }).catch(() => new Response(JSON.stringify({ events: [] })))
      ]);

      if (statsRes.ok) setStats(await statsRes.json());
      if (configRes.ok) setConfig(await configRes.json());
      if (riskRes.ok) setRiskData(await riskRes.json());
      if (eventsRes && eventsRes.ok) {
        const ev = await eventsRes.json();
        setEvents(ev.events || []);
      }
      setIsOnline(true);
    } catch {
      setIsOnline(false);
    }
  }, [selectedSubject, authToken]);

  useEffect(() => {
    fetchData();
    const timer = setInterval(() => {
      fetchData();
    }, 2500);
    return () => clearInterval(timer);
  }, [fetchData]);

  const simulate = async (type: string) => {
    setIsSimulating(true);
    try {
      let targetSubject = 'alice';
      if (type === 'rapid') targetSubject = 'attacker_1';
      else if (type === 'low_and_slow') targetSubject = 'attacker_slow';
      else if (type === 'coordinated') targetSubject = 'sybil_1';

      setSelectedSubject(targetSubject);
      setSubjectInput(targetSubject);
      await fetch(`${API_BASE}/simulate/${type}`, { method: 'POST' });
      await fetchData(targetSubject);
    } catch (err) {
      console.error(err);
    }
    setIsSimulating(false);
  };

  const reset = async () => {
    setIsSimulating(true);
    try {
      await fetch(`${API_BASE}/reset`, { method: 'POST' });
      setSelectedSubject('alice');
      setSubjectInput('');
      await fetchData('alice');
    } catch (err) {
      console.error(err);
    }
    setIsSimulating(false);
  };

  return (
    <>
      {/* BEGIN: MainHeader */}
      <header className="bg-[#111111] text-[#F5F5F5] px-6 py-3.5 flex items-center justify-between shadow-sm border-b border-[#262626] relative after:absolute after:bottom-0 after:left-0 after:right-0 after:h-[1px] after:bg-gradient-to-r after:from-[#FF3B5C]/0 after:via-[#FF3B5C]/60 after:to-[#FF3B5C]/0">
        {/* Brand Logo and Subtitle */}
        <div className="flex items-center space-x-3.5">
          {/* Shield Logo Icon */}
          <div className="flex items-center justify-center shrink-0">
            <img
              src="https://lh3.googleusercontent.com/aida-public/AB6AXuCNrNyR3WSUtFfGM6VrgbwEx5W3YT4wDBMwvdIctuRJj3_Smrnc5mN0xz7jGvWLkEYjVwKtGjJbIExISJuoxJKbcEtA6yDlhTcvIGy54TJL-sZeRAxY2CqSUUTRtHELarLG7hX3y2mXHkvDzhC8Dcr_cY56anYHRnCMsJIWHUyA03HX56YKQ5iG9CDSEssFrL3-T8d1GwaccYQ9TeHVdO1flp_NhmTuwB8ZZ0dqcgZnFBbllDXkUj0a"
              alt="Futuristic Crimson Cyber Shield Emblem"
              className="block object-contain drop-shadow-[0_0_12px_rgba(255,59,92,0.3)]"
              style={{ width: '56px', height: '56px', mixBlendMode: 'screen', filter: 'brightness(1.2) contrast(1.1)' }}
            />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-wider leading-none text-[#FF3B5C] font-sans">INTEGRITY</h1>
            <p className="text-[10px] font-mono tracking-widest text-[#A3A3A3] uppercase mt-1">DETERMINISTIC AUTH + BEHAVIORAL DEFENSE</p>
          </div>
        </div>
        {/* Status Indicator Pill */}
        <div>
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#171717] border border-[#262626] text-[#A3A3A3] text-xs font-mono tracking-wide shadow-xs">
            {/* Radio/Signal Icon with Orange/Red indicator */}
            <svg className="w-3.5 h-3.5 text-[#F97316]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 011.06 0z" strokeLinecap="round" strokeLinejoin="round"></path>
            </svg>
            <span className="text-[#F5F5F5]">{isOnline ? 'ONLINE' : 'OFFLINE'}</span>
          </div>
        </div>
      </header>
      {/* END: MainHeader */}

      {/* BEGIN: MainContentGrid */}
      <main className="flex-1 max-w-[1720px] w-full mx-auto p-5 grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* BEGIN: LeftColumn (Width 4 of 12) */}
        <div className="lg:col-span-4 flex flex-col gap-5">
          {/* Card: Security Overview */}
          <section className="bg-[#171717] rounded-2xl p-5 border border-[#262626] shadow-sm" data-purpose="security-overview-card">
            <div className="flex items-center gap-2 mb-4">
              <svg className="w-4 h-4 text-[#FF3B5C]" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24">
                <path d="M2.25 18L9 11.25l4.306 4.307a11.95 11.95 0 015.814-5.519l2.74-1.22m0 0l-5.94-2.28m5.94 2.28l-2.28 5.941" strokeLinecap="round" strokeLinejoin="round"></path>
              </svg>
              <h2 className="text-xs font-bold tracking-wider text-[#F5F5F5] uppercase font-sans">SECURITY OVERVIEW</h2>
            </div>
            <div className="grid grid-cols-2 gap-3 mb-3">
              {/* Active Subjects Metric */}
              <div className="bg-[#171717] border border-[#262626] rounded-xl p-3.5 flex flex-col justify-between shadow-xs hover:border-[#3a3a3a] transition-colors">
                <span className="text-2xl font-bold text-[#F5F5F5] leading-none">{stats?.active_subjects ?? 0}</span>
                <span className="text-[10px] font-bold text-[#A3A3A3] uppercase tracking-wide mt-3">ACTIVE SUBJECTS</span>
              </div>
              {/* Blocked Subjects Metric */}
              <div className="bg-[#201013] border border-[#DC2626]/40 rounded-xl p-3.5 flex flex-col justify-between shadow-xs hover:border-[#FF3B5C]/60 transition-colors">
                <span className="text-2xl font-bold text-[#FF3B5C] leading-none">{stats?.blocked_subjects ?? 0}</span>
                <span className="text-[10px] font-bold text-[#DC2626] uppercase tracking-wide mt-3">BLOCKED SUBJECTS</span>
              </div>
            </div>
            {/* Coordinated Attacks Metric */}
            <div className="bg-[#22140c] border border-[#F97316]/40 rounded-xl p-3.5 flex flex-col justify-between shadow-xs hover:border-[#F97316]/70 transition-colors">
              <span className="text-2xl font-bold text-[#F97316] leading-none">{Object.keys(stats?.coordinated_attacks || {}).length}</span>
              <span className="text-[10px] font-bold text-[#F97316] uppercase tracking-wide mt-3">COORDINATED ATTACKS DETECTED</span>
            </div>
          </section>

          {/* Card: System Config */}
          <section className="bg-[#171717] rounded-2xl p-5 border border-[#262626] shadow-sm" data-purpose="system-config-card">
            <div className="flex items-center gap-2 mb-4">
              <svg className="w-4 h-4 text-[#FF3B5C]" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24">
                <path d="M6.429 9.75L2.25 12l4.179 2.25m0-4.5l5.571 3 5.571-3m-11.142 0L2.25 7.5 12 2.25l9.75 5.25-4.179 2.25m0 0L21.75 12l-4.179 2.25m0 0l4.179 2.25L12 21.75 2.25 16.5l4.179-2.25m11.142 0l-5.571 3-5.571-3" strokeLinecap="round" strokeLinejoin="round"></path>
              </svg>
              <h2 className="text-xs font-bold tracking-wider text-[#F5F5F5] uppercase font-sans">SYSTEM CONFIG</h2>
            </div>
            <div className="grid grid-cols-2 gap-3">
              {/* Short Window */}
              <div>
                <span className="block text-[10px] font-bold text-[#A3A3A3] uppercase tracking-wide mb-1.5">SHORT WINDOW</span>
                <div className="bg-[#0A0A0A] border border-[#262626] rounded-xl py-2 px-3 flex items-center gap-2">
                  <svg className="w-3.5 h-3.5 text-[#FF3B5C]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <path d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" strokeLinecap="round" strokeLinejoin="round"></path>
                  </svg>
                  <span className="text-xs font-semibold text-[#F5F5F5]">{config?.short_window ?? 0}s</span>
                </div>
                <span className="block text-[10px] text-[#737373] mt-1 font-mono">Threshold: {config?.rapid_threshold ? `${config.rapid_threshold} ` : ''}uniq</span>
              </div>
              {/* Long Window */}
              <div>
                <span className="block text-[10px] font-bold text-[#A3A3A3] uppercase tracking-wide mb-1.5">LONG WINDOW</span>
                <div className="bg-[#0A0A0A] border border-[#262626] rounded-xl py-2 px-3 flex items-center gap-2">
                  <svg className="w-3.5 h-3.5 text-[#F97316]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <path d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" strokeLinecap="round" strokeLinejoin="round"></path>
                  </svg>
                  <span className="text-xs font-semibold text-[#F5F5F5]">{config?.long_window ?? 0}s</span>
                </div>
                <span className="block text-[10px] text-[#737373] mt-1 font-mono">Threshold: {config?.slow_threshold ? `${config.slow_threshold} ` : ''}uniq</span>
              </div>
            </div>
          </section>
        </div>
        {/* END: LeftColumn */}

        {/* BEGIN: CenterColumn (Width 4 of 12) */}
        <div className="lg:col-span-4 flex flex-col gap-5">
          {/* Card: Live Risk Monitor */}
          <section className="bg-[#171717] rounded-2xl p-5 border border-[#262626] shadow-sm" data-purpose="live-risk-monitor-card">
            <div className="flex items-center justify-between gap-2 mb-4">
              <div className="flex items-center gap-2">
                <svg className="w-4 h-4 text-[#FF3B5C]" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24">
                  <path d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" strokeLinecap="round" strokeLinejoin="round"></path>
                </svg>
                <h2 className="text-xs font-bold tracking-wider text-[#F5F5F5] uppercase font-sans">LIVE RISK MONITOR</h2>
              </div>
              {/* Subject Search Input */}
              <div className="relative w-40">
                <input
                  className="w-full bg-[#0A0A0A] border border-[#262626] text-[#F5F5F5] placeholder-[#737373] text-xs rounded-lg py-1 px-2.5 focus:outline-none focus:ring-1 focus:ring-[#FF3B5C] focus:border-[#FF3B5C] transition-colors"
                  placeholder="Type a subject ID..."
                  type="text"
                  value={subjectInput}
                  onChange={(e) => setSubjectInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && subjectInput.trim()) {
                      setSelectedSubject(subjectInput.trim());
                    }
                  }}
                />
              </div>
            </div>
            {/* Metric Display Panel */}
            <div className="bg-[#0A0A0A] border border-[#262626] rounded-xl p-5 flex items-center justify-between mb-5 shadow-xs">
              <div className="text-5xl font-extrabold text-[#FF3B5C] tracking-tight drop-shadow-[0_0_12px_rgba(255,59,92,0.3)]">
                {riskData?.score ?? 0}
              </div>
              <div className="flex flex-col items-end">
                <span className="text-[10px] font-bold text-[#A3A3A3] uppercase tracking-wide mb-1">STATUS</span>
                <span className="bg-[#171717] border border-[#262626] text-[#F5F5F5] text-xs font-bold px-2.5 py-0.5 rounded uppercase tracking-wide">
                  {riskData?.category?.toUpperCase() || 'NORMAL'}
                </span>
              </div>
            </div>
            {/* Score Breakdown Section Header */}
            <div className="pt-1">
              <span className="text-[10px] font-bold text-[#A3A3A3] uppercase tracking-wide">SCORE BREAKDOWN</span>
              {riskData?.contributions && Object.keys(riskData.contributions).length > 0 && (
                <div className="mt-2 space-y-1">
                  {Object.entries(riskData.contributions).map(([key, val]) => (
                    <div key={key} className="flex items-center justify-between text-[11px] font-mono">
                      <span className="text-[#A3A3A3]">{key.replace(/_/g, ' ')}</span>
                      <span className="text-[#FF3B5C] font-bold">+{Number(val)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>

          {/* Card: Live Simulator */}
          <section className="bg-[#171717] rounded-2xl p-5 border border-[#262626] shadow-sm" data-purpose="live-simulator-card">
            <div className="flex items-center gap-2 mb-4">
              <svg className="w-4 h-4 text-[#FF3B5C]" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24">
                <path d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" strokeLinecap="round" strokeLinejoin="round"></path>
              </svg>
              <h2 className="text-xs font-bold tracking-wider text-[#F5F5F5] uppercase font-sans">LIVE SIMULATOR</h2>
            </div>
            {/* Simulator 2x2 Buttons Grid */}
            <div className="grid grid-cols-2 gap-3 mb-4">
              <button
                disabled={isSimulating}
                onClick={() => simulate('normal')}
                className="bg-[#171717] hover:bg-[#202020] text-[#F5F5F5] font-bold text-xs py-3 px-4 rounded-xl shadow-xs transition-colors tracking-wide border border-[#262626] disabled:opacity-50"
              >
                NORMAL
              </button>
              <button
                disabled={isSimulating}
                onClick={() => simulate('rapid')}
                className="bg-[#1c0e11] hover:bg-[#261217] border border-[#FF3B5C] text-[#FF3B5C] font-bold text-xs py-3 px-4 rounded-xl shadow-xs transition-colors tracking-wide disabled:opacity-50"
              >
                RAPID BOLA
              </button>
              <button
                disabled={isSimulating}
                onClick={() => simulate('low_and_slow')}
                className="bg-[#1c120a] hover:bg-[#26170d] border border-[#F97316] text-[#F97316] font-bold text-xs py-3 px-4 rounded-xl shadow-xs transition-colors tracking-wide disabled:opacity-50"
              >
                LOW &amp; SLOW
              </button>
              <button
                disabled={isSimulating}
                onClick={() => simulate('coordinated')}
                className="bg-[#1b0d0e] hover:bg-[#251214] border border-[#DC2626] text-[#DC2626] font-bold text-xs py-3 px-4 rounded-xl shadow-xs transition-colors tracking-wide disabled:opacity-50"
              >
                COORDINATED
              </button>
            </div>
            {/* Reset Demo Action */}
            <div className="flex justify-center pt-2">
              <button
                disabled={isSimulating}
                onClick={reset}
                className="inline-flex items-center justify-center gap-2 bg-[#171717] hover:bg-[#222222] border border-[#262626] text-[#F5F5F5] font-bold text-xs py-2 px-5 rounded-xl shadow-xs hover:shadow-sm transition-all disabled:opacity-50"
              >
                {/* Refresh Icon */}
                <svg className={`w-3.5 h-3.5 text-[#A3A3A3] ${isSimulating ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" strokeLinecap="round" strokeLinejoin="round"></path>
                </svg>
                <span>RESET DEMO</span>
              </button>
            </div>
          </section>
        </div>
        {/* END: CenterColumn */}

        {/* BEGIN: RightColumn (Width 4 of 12) */}
        <div className="lg:col-span-4 flex flex-col h-full">
          {/* Card: Audit Timeline (Full Height) */}
          <section className="bg-[#171717] rounded-2xl p-5 border border-[#262626] shadow-sm min-h-[550px] flex flex-col" data-purpose="audit-timeline-card">
            <div className="flex items-center gap-2 mb-4">
              <svg className="w-4 h-4 text-[#FF3B5C]" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24">
                <path d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 5.625c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125" strokeLinecap="round" strokeLinejoin="round"></path>
              </svg>
              <h2 className="text-xs font-bold tracking-wider text-[#F5F5F5] uppercase font-sans">AUDIT TIMELINE</h2>
            </div>
            {/* Empty State Container or event items */}
            {events.length === 0 ? (
              <div className="flex-1 flex items-center justify-center py-20">
                <p className="text-xs font-mono text-[#737373] tracking-wide">
                  No events recorded.
                </p>
              </div>
            ) : (
              <div className="flex-1 overflow-y-auto space-y-2 max-h-[700px] pr-1">
                {events.map((ev, i) => (
                  <div key={ev.id || i} className="p-3 bg-[#0A0A0A] border border-[#262626] rounded-xl flex items-center justify-between text-xs font-mono">
                    <div>
                      <span className="font-bold text-[#F5F5F5]">{ev.subject_id}</span>
                      <span className="text-[#737373] ml-2">record #{ev.record_id}</span>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${ev.outcome === 'blocked' ? 'bg-[#201013] text-[#FF3B5C] border border-[#DC2626]/40' : ev.outcome === 'denied' ? 'bg-[#22140c] text-[#F97316] border border-[#F97316]/40' : 'bg-[#171717] text-[#A3A3A3] border border-[#262626]'}`}>
                      {ev.outcome}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
        {/* END: RightColumn */}
      </main>
      {/* END: MainContentGrid */}
    </>
  );
}
