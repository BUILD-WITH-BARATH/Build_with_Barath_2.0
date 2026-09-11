import { useState, useEffect } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  Wifi, 
  WifiOff, 
  Users, 
  Database, 
  Zap, 
  RefreshCw, 
  Clock, 
  AlertTriangle, 
  Activity, 
  CheckCircle2, 
  Radio, 
  Search, 
  ChevronRight, 
  ShieldCheck, 
  LayoutDashboard, 
  Flame, 
  AlertOctagon, 
  Fingerprint, 
  TrendingUp, 
  Workflow, 
  Lock, 
  Play, 
  RotateCcw,
  Terminal
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

function CyberGlitchText({ text, className }: { text: string; className?: string }) {
  const [displayText, setDisplayText] = useState(text);
  const chars = '01#@$%&*<>~/!_=+?';

  useEffect(() => {
    let iteration = 0;
    const interval = setInterval(() => {
      setDisplayText(
        text
          .split('')
          .map((_, index) => {
            if (index < iteration) {
              return text[index];
            }
            return chars[Math.floor(Math.random() * chars.length)];
          })
          .join('')
      );

      if (iteration >= text.length) {
        clearInterval(interval);
      }
      iteration += 1 / 1.5;
    }, 20);

    return () => clearInterval(interval);
  }, [text]);

  return <span className={className}>{displayText}</span>;
}

const rawApiBase = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
const API_BASE = rawApiBase.startsWith('http') ? rawApiBase.replace(/\/$/, '') : `https://${rawApiBase}`.replace(/\/$/, '');

type TabType = 'overview' | 'risk' | 'simulator' | 'audit' | 'architecture';

export default function App() {
  const [currentTab, setCurrentTab] = useState<TabType>('overview');
  const [stats, setStats] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [riskData, setRiskData] = useState<any>(null);
  const [config, setConfig] = useState<any>(null);
  const [selectedSubject, setSelectedSubject] = useState('alice');
  const [isOnline, setIsOnline] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [lastSimulatedVector, setLastSimulatedVector] = useState<string | null>(null);
  const [auditFilter, setAuditFilter] = useState<'all' | 'blocked' | 'denied' | 'allowed'>('all');
  const [searchFilter, setSearchFilter] = useState('');
  const [selectedEventDetail, setSelectedEventDetail] = useState<any | null>(null);
  const fetchData = async (subjectToFetch?: string) => {
    const subj = subjectToFetch !== undefined ? subjectToFetch : (selectedSubject || 'alice');
    try {
      const [statsRes, eventsRes, riskRes, configRes] = await Promise.all([
        fetch(`${API_BASE}/stats`),
        fetch(`${API_BASE}/audit-events`, { headers: { 'X-Subject': 'security_admin' } }),
        fetch(`${API_BASE}/risk/${subj || 'alice'}`),
        fetch(`${API_BASE}/config`),
      ]);
      
      if (statsRes.ok) setStats(await statsRes.json());
      if (eventsRes.ok) {
        const evData = await eventsRes.json();
        setEvents(evData.events || []);
      }
      if (riskRes.ok) setRiskData(await riskRes.json());
      if (configRes.ok) setConfig(await configRes.json());
      setIsOnline(true);
    } catch (err) {
      setIsOnline(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(() => fetchData(), 2000);
    return () => clearInterval(interval);
  }, [selectedSubject]);

  const simulate = async (type: string) => {
    setIsSimulating(true);
    setLastSimulatedVector(type);
    try {
      let targetSubject = 'alice';
      if (type === 'rapid') targetSubject = 'attacker_1';
      else if (type === 'low_and_slow') targetSubject = 'attacker_slow';
      else if (type === 'normal') targetSubject = 'alice';
      else if (type === 'coordinated') targetSubject = 'sybil_1';
      
      setSelectedSubject(targetSubject);
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
      setLastSimulatedVector(null);
      setSelectedSubject('alice');
      await fetchData('alice');
    } catch (err) {
      console.error(err);
    }
    setIsSimulating(false);
  };

  const approvePermanentBan = async (subject: string) => {
    try {
      await fetch(`${API_BASE}/admin/approve-ban/${subject}`, { method: 'POST' });
      await fetchData(subject);
    } catch (err) {
      console.error(err);
    }
  };

  const rejectPermanentBan = async (subject: string) => {
    try {
      await fetch(`${API_BASE}/admin/reject-ban/${subject}`, { method: 'POST' });
      await fetchData(subject);
    } catch (err) {
      console.error(err);
    }
  };

  const riskChartData = riskData?.contributions ? Object.entries(riskData.contributions).map(([name, value]) => ({ 
    name: name.replace(/_/g, ' '), 
    rawName: name,
    value: Number(value)
  })) : [];

  const getScoreTheme = (score: number) => {
    if (score >= 90) {
      return {
        text: 'text-rose-500',
        badge: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
        bar: '#f43f5e',
        glow: 'shadow-[0_0_50px_rgba(244,63,94,0.25)]',
        border: 'border-rose-500/40',
        bgGradient: 'from-rose-500/15 via-rose-500/5 to-transparent',
        accentBg: 'bg-rose-500 text-white',
        statusName: 'Attack / Blocked'
      };
    }
    if (score >= 70) {
      return {
        text: 'text-orange-500',
        badge: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
        bar: '#ea580c',
        glow: 'shadow-[0_0_50px_rgba(234,88,12,0.25)]',
        border: 'border-orange-500/40',
        bgGradient: 'from-orange-500/15 via-orange-500/5 to-transparent',
        accentBg: 'bg-orange-500 text-white',
        statusName: 'High Risk'
      };
    }
    if (score >= 40) {
      return {
        text: 'text-amber-500',
        badge: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
        bar: '#d97706',
        glow: 'shadow-[0_0_50px_rgba(217,119,6,0.25)]',
        border: 'border-amber-500/40',
        bgGradient: 'from-amber-500/15 via-amber-500/5 to-transparent',
        accentBg: 'bg-amber-500 text-white',
        statusName: 'Suspicious'
      };
    }
    return {
      text: 'text-emerald-400',
      badge: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
      bar: '#10b981',
      glow: 'shadow-[0_0_50px_rgba(16,185,129,0.2)]',
      border: 'border-emerald-500/40',
      bgGradient: 'from-emerald-500/15 via-emerald-500/5 to-transparent',
      accentBg: 'bg-emerald-500 text-slate-950',
      statusName: 'Normal'
    };
  };

  const currentTheme = getScoreTheme(riskData?.score || 0);

  const filteredEvents = events.filter(ev => {
    if (auditFilter === 'blocked' && ev.outcome !== 'blocked') return false;
    if (auditFilter === 'denied' && ev.outcome !== 'denied') return false;
    if (auditFilter === 'allowed' && (ev.outcome === 'blocked' || ev.outcome === 'denied')) return false;
    if (searchFilter) {
      const q = searchFilter.toLowerCase();
      return (
        ev.subject_id.toLowerCase().includes(q) ||
        String(ev.record_id).includes(q) ||
        ev.explanation.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const subjectsList = [
    { id: 'alice', label: 'alice', type: 'Normal Customer', desc: 'Legitimate object owner requests' },
    { id: 'dr_singh', label: 'dr_singh', type: 'Assigned Doctor', desc: 'Assigned records #1-#25' },
    { id: 'support_amy', label: 'support_amy', type: 'Delegated Support', desc: 'Active ticket-8431 grant on record #17' },
    { id: 'attacker_1', label: 'attacker_1', type: 'Rapid Attacker', desc: 'Burst enumeration on record IDs' },
    { id: 'attacker_slow', label: 'attacker_slow', type: 'Low & Slow Recon', desc: 'Prolonged stealth unauthorized requests' },
    { id: 'sybil_1', label: 'sybil_1', type: 'Sybil Cluster', desc: 'Coordinated distributed object enumeration' },
  ];

  const getTabTitle = (tab: TabType) => {
    switch (tab) {
      case 'overview': return 'Security Operations Center';
      case 'risk': return 'Subject Risk & Telemetry';
      case 'simulator': return 'Interactive Threat Lab';
      case 'audit': return 'Authoritative Audit Feed';
      case 'architecture': return 'Defense Pipeline Architecture';
    }
  };

  return (
    <div className="min-h-screen bg-[#090D16] text-slate-100 font-sans selection:bg-indigo-500/25 selection:text-white flex flex-col antialiased bg-cyber-grid">
      
      {/* Cyber Screen Laser Scanline & Chromatic Flash Sweep */}
      <div key={`flash-${currentTab}`} className="pointer-events-none fixed inset-0 z-50 overflow-hidden">
        <div className="absolute inset-0 animate-cyber-flash" />
        <div className="absolute inset-x-0 h-0.5 bg-gradient-to-r from-transparent via-cyan-400 to-transparent shadow-[0_0_20px_#06b6d4] animate-scanline" />
      </div>

      {/* Ambient Mesh Lighting */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        <div className="absolute -top-40 left-1/4 w-[50rem] h-[50rem] bg-indigo-500/10 rounded-full blur-[160px]"></div>
        <div className="absolute top-1/3 -right-40 w-[45rem] h-[45rem] bg-cyan-500/10 rounded-full blur-[160px]"></div>
        <div className="absolute -bottom-40 left-10 w-[45rem] h-[45rem] bg-slate-800/20 rounded-full blur-[160px]"></div>
      </div>

      <div className="flex-1 flex relative z-10">
        
        {/* Modern Left Sidebar Navigation Dock */}
        <aside className="w-20 lg:w-72 bg-[#0E1424]/95 backdrop-blur-2xl border-r border-slate-800/80 p-5 lg:p-6 flex flex-col justify-between hidden sm:flex shrink-0 min-h-screen overflow-y-auto">
          <div className="space-y-6">
            
            {/* App Brand Header */}
            <div className="flex items-center gap-3.5 px-2 py-1">
              <div className="w-11 h-11 rounded-2xl bg-gradient-to-tr from-cyan-500 via-indigo-500 to-purple-600 flex items-center justify-center text-white shadow-xl shadow-cyan-500/20 shrink-0 relative overflow-hidden group">
                <Shield className="w-6 h-6 stroke-[2.2] relative z-10" />
                <div className="absolute inset-0 bg-white/20 translate-y-full group-hover:translate-y-0 transition-transform duration-300"></div>
              </div>
              <div className="hidden lg:block">
                <div className="flex items-center gap-2">
                  <span className="text-lg font-black tracking-tight text-white font-display flex items-center gap-1.5">
                    INTEGRITY
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
                  </span>
                  <span className="px-2 py-0.5 rounded-full text-[9px] font-extrabold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 uppercase tracking-wide font-mono">
                    v2.0
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans flex items-center gap-1.5">
                  <Terminal className="w-3 h-3 text-cyan-400" />
                  BOLA Defense Engine
                </p>
              </div>
            </div>

            {/* Sidebar Navigation Tabs (Active View Switcher) */}
            <nav className="space-y-2">
              <div className="px-3 pb-1 text-[11px] font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center justify-between hidden lg:flex">
                <span>Protocols</span>
                <span className="text-slate-600 font-mono text-[10px]">05</span>
              </div>

              {[
                { id: 'overview', label: 'Security Hub', desc: 'System overview & metrics', icon: LayoutDashboard, badge: null },
                { id: 'risk', label: 'Risk Telemetry', desc: 'Subject behavioral scoring', icon: Fingerprint, badge: riskData?.score > 0 ? `${riskData.score}` : null },
                { id: 'simulator', label: 'Threat Lab', desc: 'Traffic vector injection', icon: Zap, badge: 'Active' },
                { id: 'audit', label: 'Audit Stream', desc: 'Forensic decision logs', icon: Database, badge: events.length > 0 ? `${events.length}` : null },
                { id: 'architecture', label: 'Architecture', desc: '2-Tier defense pipeline', icon: Workflow, badge: null },
              ].map(item => {
                const Icon = item.icon;
                const isActive = currentTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setCurrentTab(item.id as TabType)}
                    className={cn(
                      "w-full relative flex items-center justify-between px-3.5 py-3 rounded-2xl font-bold text-xs transition-all duration-200 text-left group overflow-hidden active:scale-[0.97] hover-glitch",
                      isActive 
                        ? "bg-slate-800/90 text-white border border-cyan-500/40 shadow-lg shadow-cyan-500/10" 
                        : "text-slate-400 hover:text-white hover:bg-slate-800/60 hover:translate-x-1 border border-transparent"
                    )}
                  >
                    {/* Active Left Indicator Bar with Cyan Glow */}
                    {isActive && (
                      <span className="absolute left-0 top-1/2 -translate-y-1/2 w-1.5 h-8 bg-gradient-to-b from-cyan-400 via-indigo-400 to-purple-400 rounded-r-full animate-cyber-indicator" />
                    )}

                    <div className="flex items-center gap-3">
                      <div className={cn(
                        "w-9 h-9 rounded-xl flex items-center justify-center transition-all duration-300 shrink-0",
                        isActive 
                          ? "bg-gradient-to-tr from-cyan-500 to-indigo-500 text-white shadow-md shadow-cyan-500/30 scale-105" 
                          : "bg-slate-800/80 text-slate-400 group-hover:text-cyan-300 group-hover:bg-slate-700/90 group-hover:scale-105"
                      )}>
                        <Icon className={cn("w-4 h-4 transition-transform duration-300", isActive ? "stroke-[2.5]" : "group-hover:rotate-6")} />
                      </div>
                      <div className="hidden lg:block">
                        <div className={cn("text-xs font-display font-bold leading-tight transition-colors", isActive ? "text-white" : "text-slate-300 group-hover:text-white")}>
                          {item.label}
                        </div>
                        <div className="text-[11px] text-slate-400 font-sans font-normal mt-0.5">{item.desc}</div>
                      </div>
                    </div>

                    <div className="flex items-center gap-1.5">
                      {item.badge && (
                        <span className={cn(
                          "hidden lg:inline-flex px-2 py-0.5 rounded-full text-[10px] font-bold font-mono transition-all",
                          isActive 
                            ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm" 
                            : "bg-slate-800 text-slate-400 group-hover:text-slate-300"
                        )}>
                          {item.badge}
                        </span>
                      )}
                      <ChevronRight className={cn(
                        "w-3.5 h-3.5 transition-all duration-200 hidden lg:block",
                        isActive 
                          ? "text-cyan-400 translate-x-0 opacity-100" 
                          : "text-slate-600 -translate-x-1.5 opacity-0 group-hover:opacity-100 group-hover:translate-x-0 group-hover:text-cyan-300"
                      )} />
                    </div>
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Sidebar Status Footer Widget */}
          <div className="hidden lg:block mt-8 pt-5 border-t border-slate-800/80">
            <div className="bg-gradient-to-b from-slate-900/90 to-slate-950/90 rounded-3xl p-5 border border-slate-800/90 shadow-xl relative overflow-hidden group hover:border-slate-700 transition-colors">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-display font-bold text-white flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
                  Engine Protected
                </span>
                <span className="text-[10px] font-mono font-bold text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded-full border border-cyan-500/30">
                  LIVE
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-sans leading-relaxed mb-3">
                Deterministic SQL authorization with real-time sliding graph telemetry.
              </p>
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-300 bg-slate-950/80 px-3 py-2 rounded-xl border border-slate-800/80">
                <span>Port: 8000</span>
                <span className="text-cyan-400 font-bold">Connected</span>
              </div>
            </div>
          </div>
        </aside>

        {/* Main Workspace Layout */}
        <div className="flex-1 flex flex-col min-w-0">
          
          {/* Top Navigation Header */}
          <header className="px-6 lg:px-10 py-5 flex items-center justify-between border-b border-slate-800/70 bg-[#090D16]/85 backdrop-blur-2xl sticky top-0 z-40">
            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-xl lg:text-2xl font-black text-white tracking-tight capitalize font-display">
                  <CyberGlitchText key={currentTab} text={getTabTitle(currentTab)} />
                </h1>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold font-mono bg-slate-900 text-cyan-400 border border-slate-700 uppercase tracking-wide flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping"></span>
                  ONLINE
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 font-sans flex items-center gap-2">
                <span className="text-slate-500 font-mono">// PROTOCOL:</span>
                <span>Deterministic Authorization + Behavioral BOLA Defense</span>
              </p>
            </div>

            <div className="flex items-center gap-3.5">
              {/* Connection Status Pill */}
              <div className={cn(
                "flex items-center gap-2.5 px-4 py-2 rounded-2xl text-xs font-bold border transition-all duration-300 font-mono",
                isOnline 
                  ? "bg-slate-900 text-slate-200 border-slate-700 shadow-sm" 
                  : "bg-rose-500/10 text-rose-400 border-rose-500/30"
              )}>
                {isOnline ? (
                  <>
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400"></span>
                    </span>
                    <Wifi className="w-4 h-4 text-cyan-400" />
                    <span className="tracking-wider text-slate-200">SECURE</span>
                  </>
                ) : (
                  <>
                    <WifiOff className="w-4 h-4 text-rose-400" />
                    <span className="tracking-wider">OFFLINE</span>
                  </>
                )}
              </div>

              {/* Reset Demo Button */}
              <button 
                disabled={isSimulating} 
                onClick={reset} 
                className="flex items-center gap-2 px-4 py-2 bg-slate-800/90 hover:bg-slate-700 text-slate-200 hover:text-white font-bold text-xs rounded-2xl border border-slate-700 transition-all active:scale-95 disabled:opacity-50 shadow-sm font-sans"
              >
                <RefreshCw className={cn("w-3.5 h-3.5", isSimulating && "animate-spin text-cyan-400")} /> 
                <span className="hidden sm:inline">Reset Matrix</span>
              </button>
            </div>
          </header>

          {/* Tab Content Container with Cyber Glitch Animation */}
          <main key={currentTab} className="p-6 lg:p-10 flex-1 max-w-[1700px] mx-auto w-full animate-cyber-glitch">
            
            {/* HUD status stream badge */}
            <div className="mb-6 flex items-center justify-between text-[11px] font-mono text-slate-400 border-b border-slate-800/60 pb-2">
              <div className="flex items-center gap-2 text-slate-300">
                <span className="inline-block w-2 h-2 bg-cyan-400 rounded-sm animate-pulse"></span>
                <span>STREAM_ID: 0x{currentTab.toUpperCase()}::SEC_NODE_01</span>
              </div>
              <div className="hidden sm:flex items-center gap-4 text-slate-400">
                <span>LATENCY: 12ms</span>
                <span>ENCRYPTION: AES-GCM-256</span>
                <span className="text-cyan-400 font-semibold">STATUS: DECRYPTED</span>
              </div>
            </div>
            
            {/* TAB 1: SECURITY HUB (OVERVIEW) */}
            {currentTab === 'overview' && (
              <div className="space-y-8 animate-in fade-in duration-300">
                
                {/* Hero Bento Stat Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
                  
                  {/* Card 1: Active Subjects */}
                  <div 
                    onClick={() => setCurrentTab('risk')}
                    className="bg-[#12192C] border border-slate-800/90 rounded-[28px] p-7 shadow-2xl relative overflow-hidden group hover:border-indigo-500/40 hover:shadow-indigo-500/10 cursor-pointer transition-all duration-300 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-4 mb-6">
                        <span className="text-xs font-bold text-slate-400 uppercase tracking-widest font-mono">Active Subjects</span>
                        <div className="w-12 h-12 rounded-2xl bg-indigo-500/15 border border-indigo-500/30 flex items-center justify-center text-indigo-400 shrink-0 group-hover:scale-110 transition-transform">
                          <Users className="w-6 h-6" />
                        </div>
                      </div>
                      <div className="flex items-center gap-4 mb-3">
                        <span className="text-5xl font-black font-display text-white tracking-tight">{stats?.active_subjects || 0}</span>
                        <span className="text-xs font-mono font-bold text-indigo-400 bg-indigo-500/15 border border-indigo-500/30 px-3 py-1 rounded-full flex items-center gap-1.5 shrink-0">
                          <TrendingUp className="w-3.5 h-3.5" /> Monitored
                        </span>
                      </div>
                    </div>
                    <p className="text-xs text-slate-400 font-sans mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between">
                      <span>Unique traffic subjects</span>
                      <ChevronRight className="w-4 h-4 text-slate-500 group-hover:translate-x-1 transition-transform shrink-0" />
                    </p>
                    <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-indigo-500 to-transparent"></div>
                  </div>

                  {/* Card 2: Blocked Subjects */}
                  <div 
                    onClick={() => setCurrentTab('audit')}
                    className="bg-[#12192C] border border-slate-800/90 rounded-[28px] p-7 shadow-2xl relative overflow-hidden group hover:border-rose-500/40 hover:shadow-rose-500/10 cursor-pointer transition-all duration-300 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-4 mb-6">
                        <span className="text-xs font-bold text-slate-400 uppercase tracking-widest font-mono">Blocked Subjects</span>
                        <div className="w-12 h-12 rounded-2xl bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-400 shrink-0 group-hover:scale-110 transition-transform">
                          <ShieldAlert className="w-6 h-6" />
                        </div>
                      </div>
                      <div className="flex items-center gap-4 mb-3">
                        <span className="text-5xl font-black font-display text-rose-400 tracking-tight">{stats?.blocked_subjects || 0}</span>
                        <span className="text-xs font-mono font-bold text-rose-400 bg-rose-500/15 border border-rose-500/30 px-3 py-1 rounded-full flex items-center gap-1.5 shrink-0">
                          <AlertOctagon className="w-3.5 h-3.5" /> Isolated
                        </span>
                      </div>
                    </div>
                    <p className="text-xs text-slate-400 font-sans mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between">
                      <span>High risk automated blocks</span>
                      <ChevronRight className="w-4 h-4 text-slate-500 group-hover:translate-x-1 transition-transform shrink-0" />
                    </p>
                    <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-rose-500 to-transparent"></div>
                  </div>

                  {/* Card 3: Coordinated Attacks */}
                  <div 
                    onClick={() => setCurrentTab('simulator')}
                    className="bg-[#12192C] border border-slate-800/90 rounded-[28px] p-7 shadow-2xl relative overflow-hidden group hover:border-cyan-500/40 hover:shadow-cyan-500/10 cursor-pointer transition-all duration-300 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-4 mb-6">
                        <span className="text-xs font-bold text-slate-400 uppercase tracking-widest font-mono">Coordinated Attacks</span>
                        <div className="w-12 h-12 rounded-2xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0 group-hover:scale-110 transition-transform">
                          <Radio className="w-6 h-6 animate-pulse" />
                        </div>
                      </div>
                      <div className="flex items-center gap-4 mb-3">
                        <span className="text-5xl font-black font-display text-cyan-400 tracking-tight">
                          {Object.keys(stats?.coordinated_attacks || {}).length}
                        </span>
                        <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-500/15 border border-cyan-500/30 px-3 py-1 rounded-full flex items-center gap-1.5 shrink-0">
                          <ShieldCheck className="w-3.5 h-3.5" /> Sybil Radar
                        </span>
                      </div>
                    </div>
                    <p className="text-xs text-slate-400 font-sans mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between">
                      <span>Multi-subject cluster attacks</span>
                      <ChevronRight className="w-4 h-4 text-slate-500 group-hover:translate-x-1 transition-transform shrink-0" />
                    </p>
                    <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 to-transparent"></div>
                  </div>

                  {/* Card 4: Quick Vector Launch */}
                  <div className="bg-gradient-to-br from-slate-900 via-[#12192C] to-[#12192C] border border-slate-800/90 rounded-[28px] p-7 shadow-2xl relative overflow-hidden flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between gap-4 mb-6">
                        <span className="text-xs font-bold text-slate-400 uppercase tracking-widest font-mono">Quick Vector</span>
                        <div className="w-12 h-12 rounded-2xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0">
                          <Flame className="w-6 h-6" />
                        </div>
                      </div>
                      <h3 className="text-lg font-bold font-display text-white mb-1">Rapid BOLA Attack</h3>
                      <p className="text-xs text-slate-400 font-sans leading-relaxed">4+ unique unauthorized requests in &lt; 30s</p>
                    </div>
                    <button 
                      disabled={isSimulating}
                      onClick={() => simulate('rapid')}
                      className="mt-6 w-full py-3.5 px-4 bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-display font-bold text-xs rounded-2xl transition-all flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 active:scale-95 disabled:opacity-50"
                    >
                      <Zap className="w-4 h-4 fill-current shrink-0" />
                      <span>Inject Rapid Vector</span>
                    </button>
                  </div>

                </div>

                {/* Overview Middle Bento Section */}
                <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
                  
                  {/* Left: Quick Subject Threat Card (7 cols) */}
                  <div className="xl:col-span-7 bg-[#12192C] border border-slate-800/90 rounded-[32px] p-8 shadow-2xl relative overflow-hidden">
                    <div className="flex items-center justify-between mb-6">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-2xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                          <Activity className="w-5 h-5" />
                        </div>
                        <div>
                          <h2 className="text-base font-display font-bold text-white">Active Threat Meter</h2>
                          <p className="text-xs text-slate-400 font-sans">Subject: <span className="font-mono text-cyan-300 font-bold">{selectedSubject || 'alice'}</span></p>
                        </div>
                      </div>

                      <button
                        onClick={() => setCurrentTab('risk')}
                        className="flex items-center gap-1.5 text-xs font-bold text-cyan-400 hover:text-cyan-300 bg-cyan-500/10 px-3 py-1.5 rounded-xl border border-cyan-500/25 transition-all font-sans"
                      >
                        <span>Deep Analysis</span>
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    {/* Threat Score Banner */}
                    <div className={cn(
                      "p-6 rounded-3xl border bg-gradient-to-r transition-all duration-300 mb-6 flex flex-col sm:flex-row items-center justify-between gap-6",
                      currentTheme.bgGradient,
                      currentTheme.border,
                      currentTheme.glow
                    )}>
                      <div className="flex items-center gap-6">
                        <div className="text-center">
                          <div className={cn("text-6xl font-black font-display tracking-tight", currentTheme.text)}>
                            {riskData?.score || 0}
                          </div>
                          <div className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest mt-1">
                            SCORE / 100
                          </div>
                        </div>

                        <div className="h-16 w-[1px] bg-slate-700/60 hidden sm:block"></div>

                        <div>
                          <div className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mb-1.5">Assessment</div>
                          <div className={cn("inline-flex px-3.5 py-1 rounded-xl text-xs font-black font-mono uppercase tracking-wide border", currentTheme.badge)}>
                            {riskData?.category || 'NORMAL'}
                          </div>
                          {riskData?.score >= 90 && (
                            <div className="text-xs font-bold text-rose-400 mt-2 flex items-center gap-1.5 font-sans">
                              <AlertOctagon className="w-4 h-4" /> BOLA BLOCK ACTIVE
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Quick subject select pills */}
                      <div className="flex flex-wrap gap-2 justify-end max-w-xs">
                        {['alice', 'dr_singh', 'attacker_1', 'attacker_slow', 'sybil_1'].map(subj => (
                          <button
                            key={subj}
                            onClick={() => setSelectedSubject(subj)}
                            className={cn(
                              "px-2.5 py-1 rounded-lg text-xs font-mono transition-all border",
                              selectedSubject === subj 
                                ? "bg-cyan-500 text-slate-950 font-bold border-cyan-400 shadow-sm shadow-cyan-500/25" 
                                : "bg-slate-900 text-slate-300 border-slate-800 hover:bg-slate-800 hover:text-white"
                            )}
                          >
                            {subj}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Chart Mini Preview */}
                    <div className="h-44 bg-slate-950/60 p-4 rounded-2xl border border-slate-800/80">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={riskChartData} layout="vertical" margin={{ top: 0, right: 20, left: 10, bottom: 0 }}>
                          <XAxis type="number" hide />
                          <YAxis dataKey="name" type="category" width={140} tick={{ fill: '#94a3b8', fontSize: 10 }} stroke="transparent" />
                          <Tooltip 
                            contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '12px', color: '#fff' }} 
                          />
                          <Bar dataKey="value" fill={currentTheme.bar} radius={[0, 6, 6, 0]} barSize={16} />
                        </BarChart>
                      </ResponsiveContainer>
                      {riskChartData.length === 0 && (
                        <div className="h-full flex items-center justify-center text-xs font-mono text-slate-500">
                          Clean Subject: No suspicious behavioral contributions
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Right: Quick Action Hub & System Windows (5 cols) */}
                  <div className="xl:col-span-5 space-y-6">
                    
                    {/* Sliding Windows Quick Widget */}
                    <div className="bg-[#12192C] border border-slate-800/90 rounded-[32px] p-7 shadow-2xl">
                      <div className="flex items-center justify-between mb-5">
                        <h3 className="text-xs font-bold font-display text-white uppercase tracking-widest flex items-center gap-2">
                          <Clock className="w-4 h-4 text-cyan-400" />
                          Sliding Window Config
                        </h3>
                        <button onClick={() => setCurrentTab('architecture')} className="text-[11px] font-sans text-slate-400 hover:text-white">
                          View Rules →
                        </button>
                      </div>

                      <div className="grid grid-cols-2 gap-4">
                        <div className="p-4 bg-slate-950/60 rounded-2xl border border-slate-800/80">
                          <div className="text-[10px] text-slate-400 uppercase font-mono font-bold tracking-wider mb-1">Short Window</div>
                          <div className="text-2xl font-black font-display text-white">{config?.short_window || 0}s</div>
                          <div className="text-[10px] text-cyan-400 mt-1 font-mono font-semibold">Threshold: {config?.rapid_threshold} uniq</div>
                        </div>

                        <div className="p-4 bg-slate-950/60 rounded-2xl border border-slate-800/80">
                          <div className="text-[10px] text-slate-400 uppercase font-mono font-bold tracking-wider mb-1">Long Window</div>
                          <div className="text-2xl font-black font-display text-white">{config?.long_window || 0}s</div>
                          <div className="text-[10px] text-amber-400 mt-1 font-mono font-semibold">Threshold: {config?.slow_threshold} uniq</div>
                        </div>
                      </div>
                    </div>

                    {/* Threat Simulator Launchers */}
                    <div className="bg-[#12192C] border border-slate-800/90 rounded-[32px] p-7 shadow-2xl">
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-xs font-bold font-display text-white uppercase tracking-widest flex items-center gap-2">
                          <Zap className="w-4 h-4 text-amber-400" />
                          Threat Simulator Testbed
                        </h3>
                        <button onClick={() => setCurrentTab('simulator')} className="text-[11px] font-sans text-slate-400 hover:text-white">
                          Full Lab →
                        </button>
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <button
                          disabled={isSimulating}
                          onClick={() => simulate('normal')}
                          className="p-3 bg-slate-800/80 hover:bg-slate-700 text-white rounded-2xl text-xs font-sans font-bold transition-all active:scale-95 text-left border border-slate-700"
                        >
                          <div className="text-[10px] text-slate-400 uppercase font-mono">200 OK</div>
                          <div>Normal Traffic</div>
                        </button>

                        <button
                          disabled={isSimulating}
                          onClick={() => simulate('rapid')}
                          className="p-3 bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 rounded-2xl text-xs font-sans font-bold transition-all active:scale-95 text-left border border-rose-500/30"
                        >
                          <div className="text-[10px] text-rose-400 uppercase font-mono">BOLA Burst</div>
                          <div>Rapid Attack</div>
                        </button>

                        <button
                          disabled={isSimulating}
                          onClick={() => simulate('low_and_slow')}
                          className="p-3 bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 rounded-2xl text-xs font-sans font-bold transition-all active:scale-95 text-left border border-amber-500/30"
                        >
                          <div className="text-[10px] text-amber-400 uppercase font-mono">Stealth</div>
                          <div>Low & Slow</div>
                        </button>

                        <button
                          disabled={isSimulating}
                          onClick={() => simulate('coordinated')}
                          className="p-3 bg-indigo-500/15 hover:bg-indigo-500/25 text-indigo-300 rounded-2xl text-xs font-sans font-bold transition-all active:scale-95 text-left border border-indigo-500/30"
                        >
                          <div className="text-[10px] text-indigo-400 uppercase font-mono">50+ Sybils</div>
                          <div>Coordinated</div>
                        </button>
                      </div>
                    </div>

                  </div>

                </div>

                {/* Recent Decision Events Feed */}
                <div className="bg-[#12192C] border border-slate-800/90 rounded-[32px] p-8 shadow-2xl">
                  <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-2xl bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-400">
                        <Database className="w-5 h-5" />
                      </div>
                      <div>
                        <h2 className="text-base font-display font-bold text-white">Live Decision Stream</h2>
                        <p className="text-xs text-slate-400 font-sans">Latest recorded access decisions</p>
                      </div>
                    </div>

                    <button
                      onClick={() => setCurrentTab('audit')}
                      className="flex items-center gap-1.5 text-xs font-bold text-cyan-400 hover:text-cyan-300 bg-cyan-500/10 px-3.5 py-2 rounded-xl border border-cyan-500/30 transition-all font-sans"
                    >
                      <span>View All {events.length} Logs</span>
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  </div>

                  <div className="space-y-3">
                    {events.slice(0, 5).map((ev: any, i: number) => (
                      <div 
                        key={i} 
                        className="p-4 rounded-2xl bg-slate-950/60 border border-slate-800/80 flex items-center justify-between gap-4 text-xs font-mono hover:bg-slate-900/60 transition-colors"
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <span className={cn(
                            "w-2.5 h-2.5 rounded-full shrink-0",
                            ev.outcome === 'blocked' ? 'bg-rose-500' : ev.outcome === 'denied' ? 'bg-orange-500' : 'bg-cyan-400'
                          )}></span>
                          <span 
                            onClick={() => { setSelectedSubject(ev.subject_id); setCurrentTab('risk'); }}
                            className="font-bold text-white hover:text-cyan-300 cursor-pointer truncate font-mono"
                          >
                            {ev.subject_id}
                          </span>
                          <span className="text-slate-500">→</span>
                          <span className="text-slate-300">GET /records/{ev.record_id}</span>
                        </div>

                        <div className="flex items-center gap-3 shrink-0">
                          <span className="text-slate-400 text-[11px]">
                            {new Date(ev.occurred_at * 1000).toLocaleTimeString()}
                          </span>
                          <span className={cn(
                            "px-2.5 py-0.5 rounded-lg text-[10px] font-bold uppercase",
                            ev.outcome === 'blocked' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                            ev.outcome === 'denied' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40' :
                            'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                          )}>
                            {ev.outcome}
                          </span>
                        </div>
                      </div>
                    ))}

                    {events.length === 0 && (
                      <div className="text-center py-8 text-xs font-mono text-slate-500">
                        No events recorded yet. Run a simulator vector to generate traffic.
                      </div>
                    )}
                  </div>
                </div>

              </div>
            )}

            {/* TAB 2: LIVE RISK MONITOR (DEEP TELEMETRY VIEW) */}
            {currentTab === 'risk' && (
              <div className="space-y-8 animate-in fade-in duration-300">
                
                {/* Subject Selector Bar */}
                <div className="bg-[#12192C] border border-slate-800/90 rounded-[32px] p-7 shadow-2xl">
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 mb-6">
                    <div>
                      <h2 className="text-lg font-black font-display text-white flex items-center gap-3">
                        <Fingerprint className="w-6 h-6 text-cyan-400" />
                        Subject Behavioral Intelligence
                      </h2>
                      <p className="text-xs text-slate-400 font-sans mt-1">Select or type any subject ID to inspect real-time risk scores and signal breakdown</p>
                    </div>

                    <div className="relative w-full lg:w-80">
                      <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                        <Search className="w-4 h-4" />
                      </div>
                      <input 
                        list="full-subject-list"
                        value={selectedSubject}
                        onChange={e => setSelectedSubject(e.target.value)}
                        placeholder="Search or enter subject ID..."
                        className="w-full bg-slate-950/80 border border-slate-700 rounded-2xl pl-10 pr-4 py-3 text-xs font-mono text-white outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20"
                      />
                      <datalist id="full-subject-list">
                        {subjectsList.map(s => (
                          <option key={s.id} value={s.id}>{s.label} ({s.type})</option>
                        ))}
                      </datalist>
                    </div>
                  </div>

                  {/* Preset Subject Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                    {subjectsList.map(s => {
                      const isSelected = selectedSubject === s.id;
                      return (
                        <div
                          key={s.id}
                          onClick={() => setSelectedSubject(s.id)}
                          className={cn(
                            "p-4 rounded-2xl border cursor-pointer transition-all duration-200",
                            isSelected 
                              ? "bg-slate-800/90 border-cyan-500/50 shadow-lg shadow-cyan-500/10" 
                              : "bg-slate-950/50 border-slate-800/80 hover:bg-slate-900/60"
                          )}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-mono font-bold text-sm text-white">{s.label}</span>
                            <span className={cn(
                              "text-[10px] font-bold font-mono px-2 py-0.5 rounded-full uppercase",
                              isSelected ? "bg-cyan-500 text-slate-950" : "bg-slate-800 text-slate-400"
                            )}>
                              {s.type}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-400 font-sans leading-snug">{s.desc}</p>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Score Dial & Detailed Analysis */}
                <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
                  
                  {/* Big Score Card (5 Cols) */}
                  <div className={cn(
                    "xl:col-span-5 p-8 rounded-[32px] border bg-gradient-to-b flex flex-col justify-between shadow-2xl relative overflow-hidden",
                    currentTheme.bgGradient,
                    currentTheme.border,
                    currentTheme.glow
                  )}>
                    <div>
                      <div className="flex items-center justify-between mb-6">
                        <span className="text-xs font-bold uppercase tracking-widest text-slate-400 font-mono">
                          INVESTIGATED: {selectedSubject || 'alice'}
                        </span>
                        <div className="flex items-center gap-2">
                          <span className={cn("px-3 py-1 rounded-xl text-xs font-black font-mono uppercase border", currentTheme.badge)}>
                            {riskData?.category || 'NORMAL'}
                          </span>
                          {riskData?.strikes > 0 && (
                            <span className={cn(
                              "px-2.5 py-1 rounded-xl text-xs font-black font-mono uppercase border",
                              riskData.strikes >= 3 ? "bg-rose-500/20 text-rose-300 border-rose-500/40" :
                              riskData.strikes === 2 ? "bg-orange-500/20 text-orange-300 border-orange-500/40" :
                              "bg-amber-500/20 text-amber-300 border-amber-500/40"
                            )}>
                              {riskData.is_permanent ? "STRIKE 3/3 (PERM BAN)" : `STRIKE ${riskData.strikes}/3`}
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="text-center my-8">
                        <div className={cn("text-8xl font-black font-display tracking-tight", currentTheme.text)}>
                          {riskData?.score || 0}
                        </div>
                        <div className="text-xs font-mono font-bold text-slate-400 tracking-widest mt-2 uppercase">
                          BEHAVIORAL RISK INDEX (0-100)
                        </div>
                      </div>

                      {/* 🛡️ Human-in-the-Loop Admin Ban Approval Box */}
                      {riskData?.is_pending_ban && (
                        <div className="mb-4 p-5 bg-amber-950/80 border border-amber-600/80 rounded-2xl shadow-xl animate-in fade-in text-left">
                          <div className="flex items-center gap-2 text-amber-300 font-bold text-xs uppercase tracking-wider mb-2 font-display">
                            <AlertTriangle className="w-4 h-4 text-amber-400 animate-bounce" />
                            Strike 3: Permanent Ban Awaiting Admin Approval
                          </div>
                          <p className="text-[11px] text-amber-200/90 mb-4 leading-relaxed font-sans">
                            This identity has triggered 3 repeat violations and is quarantined in temporary lockout. Select SecOps action:
                          </p>
                          <div className="flex flex-wrap items-center gap-2.5">
                            <button 
                              onClick={() => approvePermanentBan(selectedSubject || 'alice')}
                              className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs rounded-xl shadow-lg shadow-rose-600/30 transition-all active:scale-95 flex items-center gap-1.5"
                            >
                              🔴 Approve Permanent Ban
                            </button>
                            <button 
                              onClick={() => rejectPermanentBan(selectedSubject || 'alice')}
                              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-600 font-bold text-xs rounded-xl transition-all active:scale-95"
                            >
                              ⚪ Dismiss / Forgive (Relax Penalty)
                            </button>
                          </div>
                        </div>
                      )}

                      {riskData?.is_blocked ? (
                        <div className="p-4 rounded-2xl bg-rose-950/80 border border-rose-800 text-rose-300 text-xs font-bold flex items-center gap-3 font-sans">
                          <AlertOctagon className="w-5 h-5 shrink-0 text-rose-400 animate-pulse" />
                          <span>
                            {riskData.is_permanent 
                              ? "PERMANENT FIREWALL BAN (APPROVED BY ADMIN)" 
                              : riskData.is_pending_ban 
                              ? `STRIKE 3: QUARANTINED (${riskData.lockout_remaining_s}s)` 
                              : `ACTION BLOCKED: Lockout Active (${riskData.lockout_remaining_s}s remaining)`}
                          </span>
                        </div>
                      ) : (
                        <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-700 text-slate-200 text-xs font-bold flex items-center gap-3 font-sans">
                          <ShieldCheck className="w-5 h-5 shrink-0 text-cyan-400" />
                          <span>SAFE STATUS: Behavioral risk within normal operating parameters.</span>
                        </div>
                      )}
                    </div>

                    <div className="mt-8 pt-6 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
                      <span>Algorithm: Sliding Time-Weighted</span>
                      <span className="text-cyan-400 font-bold">TELEMETRY LIVE</span>
                    </div>
                  </div>

                  {/* Signals & Breakdown (7 Cols) */}
                  <div className="xl:col-span-7 bg-[#12192C] border border-slate-800/90 rounded-[32px] p-8 shadow-2xl flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between mb-6">
                        <div>
                          <h3 className="text-base font-display font-bold text-white">Weighted Signal Contributions</h3>
                          <p className="text-xs text-slate-400 font-sans">Components contributing to current risk score</p>
                        </div>
                        <span className="text-xs font-mono text-slate-400 bg-slate-900 px-3 py-1 rounded-xl border border-slate-800">
                          {riskChartData.length} active metrics
                        </span>
                      </div>

                      <div className="h-64 bg-slate-950/60 p-5 rounded-2xl border border-slate-800/80 mb-6">
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={riskChartData} layout="vertical" margin={{ top: 5, right: 30, left: 10, bottom: 5 }}>
                            <XAxis type="number" hide />
                            <YAxis 
                              dataKey="name" 
                              type="category" 
                              width={160} 
                              tick={{ fill: '#cbd5e1', fontSize: 11, fontWeight: 600 }} 
                              stroke="transparent" 
                            />
                            <Tooltip 
                              contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '12px', color: '#fff' }} 
                            />
                            <Bar dataKey="value" fill={currentTheme.bar} radius={[0, 8, 8, 0]} barSize={22}>
                              {riskChartData.map((_, index) => (
                                <Cell key={`cell-${index}`} fill={currentTheme.bar} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                        {riskChartData.length === 0 && (
                          <div className="h-full flex flex-col items-center justify-center text-xs font-mono text-slate-500">
                            <ShieldCheck className="w-8 h-8 text-slate-600 mb-2" />
                            <span>No risk points assessed for this subject.</span>
                          </div>
                        )}
                      </div>

                      {/* Active Detection Signals */}
                      <div>
                        <h4 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-3">Detected Behavioral Indicators</h4>
                        <div className="flex flex-wrap gap-2.5">
                          {riskData?.signals && riskData.signals.length > 0 ? (
                            riskData.signals.map((sig: string, i: number) => (
                              <span 
                                key={i} 
                                className="px-3.5 py-1.5 bg-amber-500/15 rounded-xl flex items-center gap-2 text-xs font-mono text-amber-300 border border-amber-500/30"
                              >
                                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                                <span>{sig}</span>
                              </span>
                            ))
                          ) : (
                            <span className="text-xs font-mono text-slate-500">No abnormal behavioral signals flagged.</span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                </div>

              </div>
            )}

            {/* TAB 3: THREAT SIMULATOR LAB */}
            {currentTab === 'simulator' && (
              <div className="space-y-8 animate-in fade-in duration-300">
                
                {/* Simulator Suite Cards */}
                <div className="bg-[#12192C] border border-slate-800/90 rounded-[32px] p-8 shadow-2xl">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
                    <div>
                      <h2 className="text-xl font-black font-display text-white flex items-center gap-3">
                        <Zap className="w-6 h-6 text-amber-400" />
                        Synthetic Threat Injection Lab
                      </h2>
                      <p className="text-xs text-slate-400 font-sans mt-1">Execute synthetic testbed attack patterns to validate detector efficacy in real-time</p>
                    </div>

                    <button 
                      disabled={isSimulating}
                      onClick={reset}
                      className="flex items-center gap-2 px-5 py-2.5 bg-slate-800 hover:bg-slate-700 text-white font-bold text-xs rounded-2xl border border-slate-700 transition-all active:scale-95 disabled:opacity-50 font-sans"
                    >
                      <RotateCcw className={cn("w-4 h-4", isSimulating && "animate-spin text-cyan-400")} />
                      <span>Re-seed Database & Reset Counters</span>
                    </button>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    
                    {/* Vector 1: Normal Traffic */}
                    <div className="bg-slate-950/60 border border-slate-800/90 rounded-3xl p-6 flex flex-col justify-between hover:border-cyan-500/40 transition-all">
                      <div>
                        <div className="flex items-center justify-between mb-3">
                          <span className="px-3 py-1 rounded-full text-[10px] font-mono font-bold bg-slate-900 text-cyan-400 border border-slate-700">
                            BENIGN ACCESS
                          </span>
                          <CheckCircle2 className="w-5 h-5 text-cyan-400" />
                        </div>
                        <h3 className="text-base font-bold font-display text-white">Normal User Access (Alice, Dr. Singh)</h3>
                        <p className="text-xs text-slate-400 font-sans mt-2 leading-relaxed">
                          Executes authorized queries by owner and assigned physicians. Creates valid authorization edges with zero detector blocks.
                        </p>
                      </div>
                      <button
                        disabled={isSimulating}
                        onClick={() => simulate('normal')}
                        className="mt-6 w-full py-3 bg-slate-800 hover:bg-slate-700 text-white font-display font-bold text-xs rounded-2xl transition-all flex items-center justify-center gap-2 active:scale-95 disabled:opacity-50"
                      >
                        <Play className="w-3.5 h-3.5 fill-current text-cyan-400" />
                        <span>Simulate Normal Traffic</span>
                      </button>
                    </div>

                    {/* Vector 2: Rapid BOLA */}
                    <div className="bg-slate-950/60 border border-slate-800/90 rounded-3xl p-6 flex flex-col justify-between hover:border-rose-500/40 transition-all">
                      <div>
                        <div className="flex items-center justify-between mb-3">
                          <span className="px-3 py-1 rounded-full text-[10px] font-mono font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30">
                            HIGH RATE BOLA
                          </span>
                          <Flame className="w-5 h-5 text-rose-400" />
                        </div>
                        <h3 className="text-base font-bold font-display text-white">Rapid BOLA Attack (Attacker 1)</h3>
                        <p className="text-xs text-slate-400 font-sans mt-2 leading-relaxed">
                          Attacker attempts rapid sequential record ID guessing (4+ unique unauthorized IDs within 30s). Escalates directly to automated BOLA block.
                        </p>
                      </div>
                      <button
                        disabled={isSimulating}
                        onClick={() => simulate('rapid')}
                        className="mt-6 w-full py-3 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 font-display font-bold text-xs rounded-2xl border border-rose-500/40 transition-all flex items-center justify-center gap-2 active:scale-95 disabled:opacity-50"
                      >
                        <Play className="w-3.5 h-3.5 fill-current text-rose-400" />
                        <span>Launch Rapid BOLA Attack</span>
                      </button>
                    </div>

                    {/* Vector 3: Low & Slow */}
                    <div className="bg-slate-950/60 border border-slate-800/90 rounded-3xl p-6 flex flex-col justify-between hover:border-amber-500/40 transition-all">
                      <div>
                        <div className="flex items-center justify-between mb-3">
                          <span className="px-3 py-1 rounded-full text-[10px] font-mono font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30">
                            STEALTH RECON
                          </span>
                          <Clock className="w-5 h-5 text-amber-400" />
                        </div>
                        <h3 className="text-base font-bold font-display text-white">Low & Slow Reconnaissance</h3>
                        <p className="text-xs text-slate-400 font-sans mt-2 leading-relaxed">
                          Attacker spreads unauthorized requests across prolonged sliding windows to evade short rate limits. Caught by the long-window accumulator.
                        </p>
                      </div>
                      <button
                        disabled={isSimulating}
                        onClick={() => simulate('low_and_slow')}
                        className="mt-6 w-full py-3 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 font-display font-bold text-xs rounded-2xl border border-amber-500/40 transition-all flex items-center justify-center gap-2 active:scale-95 disabled:opacity-50"
                      >
                        <Play className="w-3.5 h-3.5 fill-current text-amber-400" />
                        <span>Simulate Low & Slow Recon</span>
                      </button>
                    </div>

                    {/* Vector 4: Coordinated Sybil */}
                    <div className="bg-slate-950/60 border border-slate-800/90 rounded-3xl p-6 flex flex-col justify-between hover:border-indigo-500/40 transition-all">
                      <div>
                        <div className="flex items-center justify-between mb-3">
                          <span className="px-3 py-1 rounded-full text-[10px] font-mono font-bold bg-indigo-500/15 text-indigo-400 border border-indigo-500/30">
                            DISTRIBUTED SYBIL
                          </span>
                          <Radio className="w-5 h-5 text-indigo-400" />
                        </div>
                        <h3 className="text-base font-bold font-display text-white">Coordinated Distributed Sybil Attack</h3>
                        <p className="text-xs text-slate-400 font-sans mt-2 leading-relaxed">
                          50+ distributed identities each query single records to avoid per-user thresholds. Flagged by the global object pressure tracker.
                        </p>
                      </div>
                      <button
                        disabled={isSimulating}
                        onClick={() => simulate('coordinated')}
                        className="mt-6 w-full py-3 bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 font-display font-bold text-xs rounded-2xl border border-indigo-500/40 transition-all flex items-center justify-center gap-2 active:scale-95 disabled:opacity-50"
                      >
                        <Play className="w-3.5 h-3.5 fill-current text-indigo-400" />
                        <span>Simulate Coordinated Attack</span>
                      </button>
                    </div>

                  </div>

                  {lastSimulatedVector && (
                    <div className="mt-8 p-4 rounded-2xl bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono flex items-center justify-between">
                      <span>✓ Last executed vector: <strong className="text-cyan-400">{lastSimulatedVector}</strong></span>
                      <button 
                        onClick={() => setCurrentTab('audit')} 
                        className="text-cyan-400 underline hover:text-cyan-300 font-bold font-sans"
                      >
                        Inspect Audit Stream →
                      </button>
                    </div>
                  )}
                </div>

              </div>
            )}

            {/* TAB 4: AUDIT STREAM (FORENSIC TABLE VIEW) */}
            {currentTab === 'audit' && (
              <div className="space-y-8 animate-in fade-in duration-300">
                
                <div className="bg-[#12192C] border border-slate-800/90 rounded-[32px] p-8 shadow-2xl">
                  
                  {/* Search and Filters Bar */}
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-8">
                    <div>
                      <h2 className="text-xl font-black font-display text-white flex items-center gap-3">
                        <Database className="w-6 h-6 text-sky-400" />
                        Authoritative Decision Audit Feed
                      </h2>
                      <p className="text-xs text-slate-400 font-sans mt-1">Immutable decision record with forensic explanation trace</p>
                    </div>

                    <div className="flex flex-wrap items-center gap-3">
                      {/* Filter Tabs */}
                      <div className="flex items-center bg-slate-950/80 p-1 rounded-2xl border border-slate-800 text-xs">
                        {(['all', 'blocked', 'denied', 'allowed'] as const).map(tab => (
                          <button
                            key={tab}
                            onClick={() => setAuditFilter(tab)}
                            className={cn(
                              "px-3.5 py-1.5 rounded-xl font-bold font-display uppercase text-[10px] tracking-wider transition-all",
                              auditFilter === tab 
                                ? "bg-slate-800 text-white shadow-md border border-slate-700" 
                                : "text-slate-400 hover:text-white"
                            )}
                          >
                            {tab}
                          </button>
                        ))}
                      </div>

                      {/* Text Search Input */}
                      <div className="relative">
                        <input 
                          type="text" 
                          placeholder="Search subject, record, or reason..."
                          value={searchFilter}
                          onChange={e => setSearchFilter(e.target.value)}
                          className="bg-slate-950/80 border border-slate-700 text-xs font-mono text-white rounded-2xl px-4 py-2 outline-none focus:border-cyan-500 w-64 placeholder:text-slate-500"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Audit Table */}
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono border-collapse">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider font-mono">
                          <th className="py-3 px-4">Status</th>
                          <th className="py-3 px-4">Subject ID</th>
                          <th className="py-3 px-4">Endpoint</th>
                          <th className="py-3 px-4">Authorization</th>
                          <th className="py-3 px-4">Timestamp</th>
                          <th className="py-3 px-4">Forensic Reason</th>
                          <th className="py-3 px-4 text-right">Inspect</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {filteredEvents.map((ev: any, i: number) => {
                          const isBlocked = ev.outcome === 'blocked';
                          const isDenied = ev.outcome === 'denied';
                          return (
                            <tr key={i} className="hover:bg-slate-900/50 transition-colors">
                              <td className="py-3.5 px-4">
                                <span className={cn(
                                  "px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wider inline-block",
                                  isBlocked ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                                  isDenied ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40' :
                                  'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                                )}>
                                  {ev.outcome}
                                </span>
                              </td>

                              <td className="py-3.5 px-4">
                                <span 
                                  onClick={() => { setSelectedSubject(ev.subject_id); setCurrentTab('risk'); }}
                                  className="font-bold text-white hover:text-cyan-300 cursor-pointer underline decoration-dotted"
                                >
                                  {ev.subject_id}
                                </span>
                              </td>

                              <td className="py-3.5 px-4 text-slate-300 font-semibold">
                                GET /records/{ev.record_id}
                              </td>

                              <td className="py-3.5 px-4">
                                <span className="px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800 text-[10px] uppercase">
                                  {ev.authorization || 'NONE'}
                                </span>
                              </td>

                              <td className="py-3.5 px-4 text-slate-400">
                                {new Date(ev.occurred_at * 1000).toLocaleTimeString()}
                              </td>

                              <td className="py-3.5 px-4 text-slate-300 max-w-md truncate">
                                {ev.explanation}
                              </td>

                              <td className="py-3.5 px-4 text-right">
                                <button
                                  onClick={() => setSelectedEventDetail(ev)}
                                  className="text-xs text-cyan-400 hover:text-cyan-300 font-bold font-sans"
                                >
                                  Details
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>

                    {filteredEvents.length === 0 && (
                      <div className="py-16 text-center text-xs font-mono text-slate-500">
                        No audit events match your search criteria.
                      </div>
                    )}
                  </div>

                </div>

                {/* Event Detail Modal */}
                {selectedEventDetail && (
                  <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
                    <div className="bg-[#12192C] border border-slate-700 rounded-[32px] p-8 max-w-lg w-full shadow-2xl space-y-6 animate-in zoom-in-95 duration-200">
                      <div className="flex items-center justify-between">
                        <h3 className="text-base font-bold font-display text-white flex items-center gap-2">
                          <Database className="w-5 h-5 text-cyan-400" />
                          Audit Event Trace #{selectedEventDetail.id || 'N/A'}
                        </h3>
                        <button 
                          onClick={() => setSelectedEventDetail(null)}
                          className="text-slate-400 hover:text-white text-xs font-bold bg-slate-800 px-3 py-1 rounded-xl"
                        >
                          ✕ Close
                        </button>
                      </div>

                      <div className="space-y-3 text-xs font-mono bg-slate-950 p-5 rounded-2xl border border-slate-800">
                        <div><span className="text-slate-500">Subject:</span> <strong className="text-white">{selectedEventDetail.subject_id}</strong></div>
                        <div><span className="text-slate-500">Record ID:</span> <span className="text-white">{selectedEventDetail.record_id}</span></div>
                        <div><span className="text-slate-500">Authorization:</span> <span className="text-cyan-400">{selectedEventDetail.authorization || 'NONE'}</span></div>
                        <div><span className="text-slate-500">Outcome:</span> <span className="text-rose-400">{selectedEventDetail.outcome}</span></div>
                        <div><span className="text-slate-500">Timestamp:</span> <span className="text-slate-300">{new Date(selectedEventDetail.occurred_at * 1000).toLocaleString()}</span></div>
                        <div className="pt-2 border-t border-slate-800"><span className="text-slate-500">Full Reason:</span> <p className="text-slate-300 mt-1 leading-relaxed">{selectedEventDetail.explanation}</p></div>
                      </div>

                      <div className="flex justify-end">
                        <button 
                          onClick={() => {
                            setSelectedSubject(selectedEventDetail.subject_id);
                            setSelectedEventDetail(null);
                            setCurrentTab('risk');
                          }}
                          className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-display text-xs rounded-xl transition-all"
                        >
                          Investigate Subject Risk →
                        </button>
                      </div>
                    </div>
                  </div>
                )}

              </div>
            )}

            {/* TAB 5: ARCHITECTURE & DEFENSE PIPELINE */}
            {currentTab === 'architecture' && (
              <div className="space-y-8 animate-in fade-in duration-300">
                
                <div className="bg-[#12192C] border border-slate-800/90 rounded-[32px] p-8 shadow-2xl">
                  <div className="mb-8">
                    <h2 className="text-xl font-black font-display text-white flex items-center gap-3">
                      <Workflow className="w-6 h-6 text-cyan-400" />
                      Two-Tiered BOLA Defense Architecture
                    </h2>
                    <p className="text-xs text-slate-400 font-sans mt-1">Authoritative zero-trust policy separation from behavioral telemetry</p>
                  </div>

                  {/* Visual Node Flow */}
                  <div className="bg-slate-950/70 p-8 rounded-3xl border border-slate-800/80 space-y-6 max-w-4xl mx-auto font-mono text-xs">
                    
                    {/* Node 1: Request */}
                    <div className="flex flex-col items-center">
                      <div className="px-6 py-3 bg-slate-900 border border-slate-700 rounded-2xl font-bold font-mono text-white shadow-md">
                        HTTP API REQUEST (GET /records/:id with X-Subject)
                      </div>
                      <div className="h-6 w-[2px] bg-slate-700 my-1"></div>
                    </div>

                    {/* Node 2: Layer 1 SQL Auth */}
                    <div className="p-6 bg-gradient-to-br from-slate-900 to-slate-950 border border-cyan-500/40 rounded-3xl shadow-xl">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-2 text-cyan-400 font-display font-bold text-sm">
                          <Lock className="w-4 h-4" />
                          <span>LAYER 1: DETERMINISTIC SQL AUTHORIZATION</span>
                        </div>
                        <span className="text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 px-2.5 py-0.5 rounded-full uppercase font-mono font-bold">
                          Authoritative
                        </span>
                      </div>
                      <p className="text-slate-400 text-xs leading-relaxed mb-4 font-sans">
                        Only database records, physician assignments, or active time-bound grants can authorize access. A learned graph never grants permission.
                      </p>

                      <div className="grid grid-cols-2 gap-4 text-center font-bold">
                        <div className="p-3 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-mono">
                          ✓ YES: Assigned / Owner → 200 OK
                        </div>
                        <div className="p-3 rounded-2xl bg-rose-500/15 border border-rose-500/30 text-rose-400 font-mono">
                          ✕ NO: Unauthorized → 403 Forbidden
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-col items-center">
                      <div className="h-6 w-[2px] bg-slate-700 my-1"></div>
                    </div>

                    {/* Node 3: Layer 2 Behavioral Engine */}
                    <div className="p-6 bg-gradient-to-br from-slate-900 to-slate-950 border border-amber-500/40 rounded-3xl shadow-xl">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-2 text-amber-400 font-display font-bold text-sm">
                          <Activity className="w-4 h-4" />
                          <span>LAYER 2: BEHAVIORAL GRAPH & ENUMERATION DETECTOR</span>
                        </div>
                        <span className="text-[10px] bg-amber-500/15 text-amber-400 border border-amber-500/30 px-2.5 py-0.5 rounded-full uppercase font-mono font-bold">
                          Telemetry
                        </span>
                      </div>
                      <p className="text-slate-400 text-xs leading-relaxed mb-4 font-sans">
                        Tracks sliding window object counts, sequential ID transitions, and distributed Sybil clusters. Escalates to automated blocking if threshold breached.
                      </p>

                      <div className="p-4 rounded-2xl bg-rose-500/20 border border-rose-500/40 text-center font-mono font-bold text-rose-300">
                        IF RISK SCORE &gt;= 90 OR 4+ DENIALS IN 30s → TEMPORARY BOLA BLOCK
                      </div>
                    </div>

                    <div className="flex flex-col items-center">
                      <div className="h-6 w-[2px] bg-slate-700 my-1"></div>
                    </div>

                    {/* Node 4: Progressive 3-Strike Escalation & HITL Governance */}
                    <div className="p-6 bg-gradient-to-br from-slate-900 to-slate-950 border border-indigo-500/40 rounded-3xl shadow-xl">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-2 text-indigo-400 font-display font-bold text-sm">
                          <ShieldAlert className="w-4 h-4" />
                          <span>PROGRESSIVE 3-STRIKE POLICY &amp; HUMAN-IN-THE-LOOP GOVERNANCE</span>
                        </div>
                        <span className="text-[10px] bg-indigo-500/15 text-indigo-400 border border-indigo-500/30 px-2.5 py-0.5 rounded-full uppercase font-mono font-bold">
                          Governance
                        </span>
                      </div>
                      <p className="text-slate-400 text-xs leading-relaxed mb-4 font-sans">
                        Enforces escalating penalties for repeat attacks while preventing accidental rogue lockouts via required administrator review on Strike 3.
                      </p>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-center font-mono text-xs">
                        <div className="p-3 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-amber-300">
                          <div className="font-bold">Strike 1: Soft Lockout</div>
                          <div className="text-[10px] text-slate-400 mt-0.5">2m Cool-off (Typo safety)</div>
                        </div>
                        <div className="p-3 rounded-2xl bg-orange-500/15 border border-orange-500/30 text-orange-300">
                          <div className="font-bold">Strike 2: Hard Lockout</div>
                          <div className="text-[10px] text-slate-400 mt-0.5">30m Isolation + SOC Alert</div>
                        </div>
                        <div className="p-3 rounded-2xl bg-rose-500/20 border border-rose-500/40 text-rose-300">
                          <div className="font-bold">Strike 3: HITL Review</div>
                          <div className="text-[10px] text-rose-400 mt-0.5 font-bold">Quarantine + Admin Approval</div>
                        </div>
                      </div>
                    </div>

                  </div>
                </div>

              </div>
            )}

          </main>

        </div>

      </div>

    </div>
  );
}
