import { useState, useRef } from 'react';
import { Hero } from './components/Hero';
import { DemoPage } from './components/DemoPage';

const rawApiBase = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
const API_BASE = rawApiBase.startsWith('http') ? rawApiBase.replace(/\/$/, '') : `https://${rawApiBase}`.replace(/\/$/, '');

function App() {
  const [isOnline, setIsOnline] = useState<boolean | null>(null);
  const demoRef = useRef<HTMLDivElement>(null);

  useState(() => {
    fetch(`${API_BASE}/config`)
      .then((r) => setIsOnline(r.ok))
      .catch(() => setIsOnline(false));
  });

  const scrollToDemo = () => {
    demoRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#F5F5F5] flex flex-col">
      <header className="sticky top-0 z-10 bg-[#0A0A0A]/90 backdrop-blur border-b border-[#262626] px-6 py-3 flex items-center justify-between">
        <span className="font-bold tracking-wide">INTEGRITY</span>
        <div className="flex items-center gap-3">
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#171717] border border-[#262626] text-xs font-mono text-[#A3A3A3]">
            <span
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: isOnline === null ? '#525252' : isOnline ? '#22D3A6' : '#FF3B5C' }}
            />
            {isOnline === null ? 'checking backend...' : isOnline ? 'backend live' : 'backend unreachable'}
          </span>
          <button
            onClick={scrollToDemo}
            className="px-3.5 py-1.5 rounded-lg bg-[#FF3B5C] text-black font-bold text-xs font-mono hover:bg-[#ff5470] transition-all"
          >
            LIVE DEMO
          </button>
        </div>
      </header>

      <Hero onSeeDemo={scrollToDemo} />

      <div ref={demoRef} className="border-t border-[#262626]">
        <DemoPage apiBase={API_BASE} />
      </div>

      <footer className="border-t border-[#262626] px-6 py-6 text-center text-xs text-[#525252] font-mono">
        INTEGRITY — deterministic authorization + behavioral defense for API object access
      </footer>
    </div>
  );
}

export default App;
