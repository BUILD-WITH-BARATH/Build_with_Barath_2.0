import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, Wifi, WifiOff, Users, Database, Zap, RefreshCw, Layers, Clock, AlertTriangle, Activity } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

export default function App() {
  const [stats, setStats] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [riskData, setRiskData] = useState<any>(null);
  const [config, setConfig] = useState<any>(null);
  const [selectedSubject, setSelectedSubject] = useState('');
  const [isOnline, setIsOnline] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, eventsRes, riskRes, configRes] = await Promise.all([
          fetch(`${API_BASE}/stats`),
          fetch(`${API_BASE}/audit-events`, { headers: { 'X-Subject': 'security_admin' } }),
          fetch(`${API_BASE}/risk/${selectedSubject || 'alice'}`), // default fallback
          fetch(`${API_BASE}/config`),
        ]);
        
        setStats(await statsRes.json());
        const evData = await eventsRes.json();
        setEvents(evData.events || []);
        setRiskData(await riskRes.json());
        setConfig(await configRes.json());
        setIsOnline(true);
      } catch (err) {
        setIsOnline(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, [selectedSubject]);

  const simulate = async (type: string) => {
    setIsSimulating(true);
    try {
      await fetch(`${API_BASE}/simulate/${type}`, { method: 'POST' });
    } catch (err) {
      console.error(err);
    }
    setIsSimulating(false);
  };

  const reset = async () => {
    try {
      await fetch(`${API_BASE}/reset`, { method: 'POST' });
    } catch (err) {
      console.error(err);
    }
  };

  const riskChartData = riskData?.contributions ? Object.entries(riskData.contributions).map(([name, value]) => ({ name, value })) : [];

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 font-sans selection:bg-emerald-500/30">
      {/* Elegant Royal Green Header */}
      <header className="bg-[#064e3b] text-white shadow-lg sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-emerald-300" />
            <div>
              <h1 className="text-lg font-bold tracking-tight text-white">INTEGRITY</h1>
              <p className="text-[10px] uppercase tracking-widest text-emerald-200/80 font-semibold">Deterministic Auth + Behavioral Defense</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className={cn("flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold bg-white/10 backdrop-blur border border-white/20", 
              isOnline ? "text-emerald-300" : "text-rose-300"
            )}>
              {isOnline ? <><Wifi className="w-3.5 h-3.5" /> PROTECTED</> : <><WifiOff className="w-3.5 h-3.5" /> OFFLINE</>}
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 py-8 grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column */}
        <div className="space-y-6">
          <section className="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm">
            <h2 className="text-sm font-bold flex items-center gap-2 text-[#064e3b] mb-4 uppercase tracking-wider"><Activity className="w-4 h-4"/> Security Overview</h2>
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-slate-50 rounded-xl p-4 border border-slate-100">
                <div className="text-2xl font-black text-slate-800">{stats?.active_subjects || 0}</div>
                <div className="text-[10px] uppercase text-slate-500 font-bold tracking-wider mt-1">Active Subjects</div>
              </div>
              <div className="bg-rose-50 rounded-xl p-4 border border-rose-100 relative overflow-hidden">
                <div className="text-2xl font-black text-rose-700">{stats?.blocked_subjects || 0}</div>
                <div className="text-[10px] uppercase text-rose-500 font-bold tracking-wider mt-1">Blocked Subjects</div>
              </div>
              <div className="bg-emerald-50 rounded-xl p-4 border border-emerald-100 col-span-2">
                <div className="text-xl font-black text-emerald-800">{Object.keys(stats?.coordinated_attacks || {}).length}</div>
                <div className="text-[10px] uppercase text-emerald-600 font-bold tracking-wider mt-1">Coordinated Attacks Detected</div>
              </div>
            </div>
          </section>

          <section className="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm">
            <h2 className="text-sm font-bold mb-4 flex items-center gap-2 text-[#064e3b] uppercase tracking-wider"><Layers className="w-4 h-4"/> System Config</h2>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <div className="text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Short Window</div>
                <div className="font-mono text-slate-700 bg-slate-50 px-3 py-2 rounded-lg border border-slate-100 flex items-center gap-2"><Clock className="w-3 h-3 text-emerald-600"/> {config?.short_window || 0}s</div>
                <div className="text-[9px] text-slate-400 mt-1">Threshold: {config?.rapid_threshold} uniq</div>
              </div>
              <div>
                <div className="text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1">Long Window</div>
                <div className="font-mono text-slate-700 bg-slate-50 px-3 py-2 rounded-lg border border-slate-100 flex items-center gap-2"><Clock className="w-3 h-3 text-amber-600"/> {config?.long_window || 0}s</div>
                <div className="text-[9px] text-slate-400 mt-1">Threshold: {config?.slow_threshold} uniq</div>
              </div>
            </div>
          </section>

          <section className="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm">
            <h2 className="text-sm font-bold mb-4 flex items-center gap-2 text-[#064e3b] uppercase tracking-wider"><ShieldAlert className="w-4 h-4"/> Architecture</h2>
            <div className="bg-slate-50 border border-slate-100 rounded-xl p-4 text-[11px] font-mono leading-relaxed text-slate-600">
              <div className="text-center font-bold text-slate-800 mb-2">REQUEST</div>
              <div className="text-center">↓</div>
              <div className="bg-white py-1.5 text-center rounded border border-slate-200 text-[#064e3b] font-bold my-1 shadow-sm">LAYER 1: SQL AUTHORIZATION</div>
              <div className="flex justify-between px-2 my-2">
                <div className="text-emerald-600 text-center border-t border-emerald-200 pt-1 w-1/2 mx-1">YES → 200 OK</div>
                <div className="text-rose-600 text-center border-t border-rose-200 pt-1 w-1/2 mx-1">NO → 403 DENY</div>
              </div>
              <div className="text-center">↓</div>
              <div className="bg-white py-1.5 text-center rounded border border-slate-200 text-amber-600 font-bold my-1 shadow-sm">LAYER 2: BEHAVIORAL ENGINE</div>
              <div className="text-center">↓</div>
              <div className="text-center text-rose-600 font-bold">RISK &gt; 90 → BLOCK</div>
            </div>
          </section>
        </div>

        {/* Middle Column */}
        <div className="space-y-6">
          <section className="bg-white border border-slate-200 rounded-2xl p-6 shadow-md relative overflow-hidden">
            
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-sm font-bold flex items-center gap-2 text-[#064e3b] uppercase tracking-wider"><Users className="w-4 h-4"/> Live Risk Monitor</h2>
              <div className="relative">
                <input 
                  list="subject-list"
                  value={selectedSubject} 
                  onChange={e => setSelectedSubject(e.target.value)}
                  className="bg-slate-50 border border-slate-200 text-xs font-mono rounded-lg px-3 py-1.5 outline-none focus:border-[#064e3b] focus:ring-1 focus:ring-[#064e3b] transition-all w-48 text-slate-800"
                  placeholder="Type a subject ID..."
                />
                <datalist id="subject-list">
                  <option value="alice">alice (normal)</option>
                  <option value="attacker_1">attacker_1 (rapid)</option>
                  <option value="attacker_slow">attacker_slow (slow)</option>
                  <option value="sybil_1">sybil_1 (coordinated)</option>
                </datalist>
              </div>
            </div>

            <div className="flex items-center gap-6 mb-8 bg-slate-50 p-5 rounded-xl border border-slate-100 shadow-inner">
               <div className="flex flex-col items-center justify-center min-w-[80px]">
                 <div className="text-5xl font-black tracking-tighter" style={{ color: riskData?.score >= 90 ? '#e11d48' : riskData?.score >= 70 ? '#d97706' : riskData?.score >= 40 ? '#d97706' : '#059669'}}>
                   {riskData?.score || 0}
                 </div>
               </div>
               <div className="h-16 w-[1px] bg-slate-200"></div>
               <div className="flex-1">
                  <div className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1">Status</div>
                  <div className={cn("inline-flex px-3 py-1 rounded-md text-xs font-bold font-mono", 
                    riskData?.category === 'Attack' ? 'bg-rose-100 text-rose-700 border border-rose-200' :
                    riskData?.category === 'High Risk' ? 'bg-orange-100 text-orange-700 border border-orange-200' :
                    riskData?.category === 'Suspicious' ? 'bg-amber-100 text-amber-700 border border-amber-200' :
                    'bg-emerald-100 text-emerald-700 border border-emerald-200'
                  )}>
                    {riskData?.category || 'NORMAL'}
                  </div>
                  {riskData?.score >= 90 && <div className="text-xs text-rose-600 font-bold mt-2 flex items-center gap-1"><AlertTriangle className="w-3 h-3"/> ACTION BLOCKED</div>}
               </div>
            </div>

            <h3 className="text-[10px] font-bold mb-4 text-slate-500 uppercase tracking-wider">Score Breakdown</h3>
            <div className="h-48 mb-4">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={riskChartData} layout="vertical" margin={{ top: 0, right: 30, left: 0, bottom: 0 }}>
                  <XAxis type="number" hide />
                  <YAxis dataKey="name" type="category" width={140} tick={{fill: '#64748b', fontSize: 9}} stroke="transparent" />
                  <Tooltip cursor={{fill: '#f1f5f9'}} contentStyle={{backgroundColor: '#ffffff', border: '1px solid #e2e8f0', fontSize: '12px', borderRadius: '8px', color: '#0f172a'}} />
                  <Bar dataKey="value" fill="#064e3b" radius={[0, 4, 4, 0]} barSize={20} />
                </BarChart>
              </ResponsiveContainer>
              {riskChartData.length === 0 && <div className="text-center text-slate-400 text-xs py-10 font-mono">No suspicious contributions.</div>}
            </div>
            
            {riskData?.signals && riskData.signals.length > 0 && (
              <div className="mt-6 pt-5 border-t border-slate-100">
                <h3 className="text-[10px] font-bold mb-3 text-slate-500 uppercase tracking-wider">Detection Signals</h3>
                <div className="flex flex-wrap gap-2">
                  {riskData.signals.map((sig: string, i: number) => (
                    <span key={i} className="px-2.5 py-1 bg-amber-50 rounded flex items-center gap-1.5 text-[10px] font-mono text-amber-800 border border-amber-200">
                      <AlertTriangle className="w-3 h-3 text-amber-500"/> {sig}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </section>

          <section className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
            <h2 className="text-sm font-bold mb-5 flex items-center gap-2 text-[#064e3b] uppercase tracking-wider"><Zap className="w-4 h-4"/> Live Simulator</h2>
            <div className="grid grid-cols-2 gap-3">
               <button disabled={isSimulating} onClick={() => simulate('normal')} className="px-4 py-3 bg-[#064e3b] hover:bg-[#064e3b]/90 text-white text-xs font-semibold uppercase tracking-wider rounded-xl transition-all active:scale-95 disabled:opacity-50">
                 Normal
               </button>
               <button disabled={isSimulating} onClick={() => simulate('rapid')} className="px-4 py-3 bg-white hover:bg-rose-50 text-rose-700 text-xs font-semibold uppercase tracking-wider rounded-xl border border-rose-200 transition-all active:scale-95 disabled:opacity-50 shadow-sm">
                 Rapid BOLA
               </button>
               <button disabled={isSimulating} onClick={() => simulate('low_and_slow')} className="px-4 py-3 bg-white hover:bg-amber-50 text-amber-700 text-xs font-semibold uppercase tracking-wider rounded-xl border border-amber-200 transition-all active:scale-95 disabled:opacity-50 shadow-sm">
                 Low & Slow
               </button>
               <button disabled={isSimulating} onClick={() => simulate('coordinated')} className="px-4 py-3 bg-white hover:bg-indigo-50 text-indigo-700 text-xs font-semibold uppercase tracking-wider rounded-xl border border-indigo-200 transition-all active:scale-95 disabled:opacity-50 shadow-sm">
                 Coordinated
               </button>
            </div>
            <div className="mt-5 pt-5 border-t border-slate-100 flex justify-end">
              <button disabled={isSimulating} onClick={reset} className="flex items-center gap-2 px-5 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold text-xs uppercase tracking-wider rounded-lg transition-all active:scale-95 disabled:opacity-50">
                <RefreshCw className={cn("w-4 h-4", isSimulating && "animate-spin")} /> Reset Demo
              </button>
            </div>
          </section>
        </div>

        {/* Right Column */}
        <div className="space-y-6">
          <section className="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm h-full flex flex-col relative overflow-hidden">
            <h2 className="text-sm font-bold mb-4 flex items-center gap-2 text-[#064e3b] uppercase tracking-wider"><Database className="w-4 h-4"/> Audit Timeline</h2>
            
            <div className="flex-1 overflow-y-auto pr-2 space-y-3 relative z-10" style={{ maxHeight: 'calc(100vh - 200px)' }}>
              {events.slice(0, 50).map((ev: any, i: number) => (
                <div key={i} className={cn("p-3.5 rounded-xl border text-[11px] font-mono flex items-start gap-3 transition-colors", 
                  ev.outcome === 'blocked' ? "bg-rose-50 border-rose-200" : 
                  ev.outcome === 'denied' ? "bg-orange-50 border-orange-200" : 
                  "bg-slate-50 border-slate-100"
                )}>
                  <div className={cn("w-2 h-2 rounded-full mt-1.5 flex-shrink-0", 
                    ev.outcome === 'blocked' ? "bg-rose-500" : 
                    ev.outcome === 'denied' ? "bg-orange-500" : 
                    "bg-emerald-500"
                  )}></div>
                  <div className="flex-1 min-w-0">
                    <div className="flex justify-between items-center mb-1.5">
                      <span 
                        onClick={() => setSelectedSubject(ev.subject_id)}
                        className={cn("font-bold truncate text-[12px] cursor-pointer hover:underline", 
                          ev.outcome === 'blocked' || ev.outcome === 'denied' ? "text-rose-700" : "text-emerald-700"
                        )}
                        title={`Click to investigate ${ev.subject_id}`}
                      >
                        {ev.subject_id}
                      </span>
                      <span className="text-[9px] text-slate-400">{new Date(ev.occurred_at * 1000).toLocaleTimeString()}</span>
                    </div>
                    <div className="text-slate-700 truncate font-semibold">GET /records/{ev.record_id}</div>
                    <div className="text-slate-500 mt-1 truncate">{ev.explanation}</div>
                    <div className="flex gap-2 mt-2">
                      <span className="text-[9px] px-1.5 py-0.5 bg-white rounded text-slate-500 border border-slate-200 uppercase">
                        Auth: {ev.authorization || 'NONE'}
                      </span>
                      {ev.outcome === 'blocked' && <span className="text-[9px] px-1.5 py-0.5 bg-rose-100 rounded text-rose-700 border border-rose-200 font-bold uppercase tracking-wider">BLOCKED</span>}
                    </div>
                  </div>
                </div>
              ))}
              {events.length === 0 && (
                <div className="text-center text-slate-400 py-10 text-xs font-mono">No events recorded.</div>
              )}
            </div>
            
            {/* Soft fade at bottom for scrolling */}
            <div className="absolute bottom-0 left-0 right-0 h-12 bg-gradient-to-t from-white to-transparent z-20 pointer-events-none"></div>
          </section>
        </div>
      </div>
    </div>
  );
}
