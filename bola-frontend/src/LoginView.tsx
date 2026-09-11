import { useState } from 'react';

export interface DemoAccount {
  id: string;
  label: string;
  role: string;
  pwd: string;
  badge: string;
  icon: string;
}

export const DEMO_ACCOUNTS: DemoAccount[] = [
  { id: 'security_admin', label: 'SOC Admin', role: 'security_admin', pwd: 'admin_changeme123', badge: 'border-[#FF3B5C]/60 text-[#FF3B5C] bg-[#201013]', icon: '🛡️' },
  { id: 'alice', label: 'Alice (Owner 1-50)', role: 'customer', pwd: 'changeme123', badge: 'border-[#404040] text-[#F5F5F5] bg-[#1a1a1a]', icon: '👤' },
  { id: 'bob', label: 'Bob (Owner 51-100)', role: 'customer', pwd: 'changeme123', badge: 'border-[#404040] text-[#F5F5F5] bg-[#1a1a1a]', icon: '👤' },
  { id: 'dr_singh', label: 'Dr. Singh (Assigned)', role: 'doctor', pwd: 'changeme123', badge: 'border-emerald-500/50 text-emerald-400 bg-emerald-950/30', icon: '🩺' },
  { id: 'attacker_1', label: 'Attacker 1 (Threat)', role: 'customer', pwd: 'changeme123', badge: 'border-orange-500/50 text-orange-400 bg-orange-950/30', icon: '🥷' },
];

export function LoginView({
  onLogin,
  isLoggingIn,
  loginError,
  isOnline,
}: {
  onLogin: (subject?: string, password?: string) => Promise<void>;
  isLoggingIn: boolean;
  loginError: string | null;
  isOnline: boolean;
}) {
  const [subject, setSubject] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onLogin(subject, password);
  };

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#F5F5F5] flex flex-col justify-between selection:bg-[#FF3B5C]/30 selection:text-[#FF3B5C] relative overflow-hidden font-sans">
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-[#FF3B5C]/5 blur-[140px] rounded-full pointer-events-none"></div>

      <header className="px-6 py-4 flex items-center justify-between border-b border-[#262626]/50 backdrop-blur-sm z-10">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-[#FF3B5C] animate-ping"></div>
          <span className="text-[11px] font-mono tracking-widest text-[#A3A3A3] uppercase">
            INTEGRITY SOC · ACCESS AUTHENTICATOR
          </span>
        </div>
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#171717] border border-[#262626] text-[#A3A3A3] text-xs font-mono">
          <span className={`w-2 h-2 rounded-full ${isOnline ? 'bg-emerald-500' : 'bg-orange-500'}`}></span>
          <span>{isOnline ? 'BACKEND ONLINE' : 'BACKEND OFFLINE'}</span>
        </div>
      </header>

      <main className="flex-1 flex items-center justify-center p-4 z-10">
        <div className="w-full max-w-md bg-[#171717] border border-[#262626] rounded-2xl p-7 shadow-2xl relative after:absolute after:bottom-0 after:left-0 after:right-0 after:h-[1px] after:bg-gradient-to-r after:from-[#FF3B5C]/0 after:via-[#FF3B5C]/70 after:to-[#FF3B5C]/0">
          <div className="text-center mb-6">
            <div className="inline-flex items-center justify-center mb-3">
              <img
                src="https://lh3.googleusercontent.com/aida-public/AB6AXuCNrNyR3WSUtFfGM6VrgbwEx5W3YT4wDBMwvdIctuRJj3_Smrnc5mN0xz7jGvWLkEYjVwKtGjJbIExISJuoxJKbcEtA6yDlhTcvIGy54TJL-sZeRAxY2CqSUUTRtHELarLG7hX3y2mXHkvDzhC8Dcr_cY56anYHRnCMsJIWHUyA03HX56YKQ5iG9CDSEssFrL3-T8d1GwaccYQ9TeHVdO1flp_NhmTuwB8ZZ0dqcgZnFBbllDXkUj0a"
                alt="Futuristic Crimson Cyber Shield Emblem"
                className="block object-contain drop-shadow-[0_0_16px_rgba(255,59,92,0.4)]"
                style={{ width: '64px', height: '64px', mixBlendMode: 'screen', filter: 'brightness(1.2) contrast(1.1)' }}
              />
            </div>
            <h1 className="text-xl font-bold tracking-wider text-[#FF3B5C]">INTEGRITY</h1>
            <p className="text-[10px] font-mono tracking-widest text-[#A3A3A3] uppercase mt-1">
              DETERMINISTIC AUTH + BEHAVIORAL DEFENSE
            </p>
            <div className="mt-2 inline-block px-2.5 py-0.5 rounded bg-[#0A0A0A] border border-[#262626] text-[10px] font-mono text-[#737373]">
              OWASP API1:2023 · ZERO TRUST GATEWAY
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-[10px] font-bold text-[#A3A3A3] uppercase tracking-wide mb-1.5">
                IDENTITY (SUBJECT ID)
              </label>
              <input
                type="text"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="e.g. security_admin or alice"
                className="w-full bg-[#0A0A0A] border border-[#262626] text-[#F5F5F5] placeholder-[#737373] text-xs font-mono rounded-xl py-2.5 px-3.5 focus:outline-none focus:border-[#FF3B5C] focus:ring-1 focus:ring-[#FF3B5C] transition-all"
                autoComplete="username"
                required
              />
            </div>

            <div>
              <label className="block text-[10px] font-bold text-[#A3A3A3] uppercase tracking-wide mb-1.5">
                ACCESS KEY (PASSWORD)
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-[#0A0A0A] border border-[#262626] text-[#F5F5F5] placeholder-[#737373] text-xs font-mono rounded-xl py-2.5 px-3.5 pr-12 focus:outline-none focus:border-[#FF3B5C] focus:ring-1 focus:ring-[#FF3B5C] transition-all"
                  autoComplete="current-password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#737373] hover:text-[#A3A3A3] text-[10px] font-mono transition-colors"
                >
                  {showPassword ? 'HIDE' : 'SHOW'}
                </button>
              </div>
            </div>

            {loginError && (
              <div className="p-3 bg-[#201013] border border-[#DC2626]/50 rounded-xl text-xs font-mono text-[#FF3B5C] flex items-center gap-2">
                <svg className="w-4 h-4 shrink-0 text-[#FF3B5C]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" strokeLinecap="round" strokeLinejoin="round"></path>
                </svg>
                <span>{loginError}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={isLoggingIn}
              className="w-full bg-[#FF3B5C] hover:bg-[#e03150] active:scale-[0.99] text-[#0A0A0A] font-bold text-xs py-3 px-4 rounded-xl shadow-lg shadow-[#FF3B5C]/20 transition-all tracking-wider uppercase flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {isLoggingIn ? (
                <span className="inline-block animate-spin">⟳</span>
              ) : (
                <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24">
                  <path d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15M12 9l-3 3m0 0l3 3m-3-3h12.75" strokeLinecap="round" strokeLinejoin="round"></path>
                </svg>
              )}
              <span>{isLoggingIn ? 'AUTHENTICATING...' : 'AUTHENTICATE & ENTER SOC'}</span>
            </button>
          </form>

          <div className="mt-6 pt-5 border-t border-[#262626]">
            <span className="block text-[10px] font-bold text-[#737373] uppercase tracking-wider text-center mb-2.5">
              OR INSTANT 1-CLICK DEMO AUTHENTICATION
            </span>
            <div className="grid grid-cols-1 gap-1.5">
              {DEMO_ACCOUNTS.map((acc) => (
                <button
                  key={acc.id}
                  type="button"
                  disabled={isLoggingIn}
                  onClick={() => onLogin(acc.id, acc.pwd)}
                  className="flex items-center justify-between p-2 rounded-xl bg-[#0A0A0A] border border-[#262626] hover:border-[#FF3B5C]/50 hover:bg-[#151515] transition-all text-left text-xs font-mono group disabled:opacity-50"
                >
                  <div className="flex items-center gap-2">
                    <span>{acc.icon}</span>
                    <span className="font-semibold text-[#F5F5F5] group-hover:text-[#FF3B5C] transition-colors">{acc.id}</span>
                  </div>
                  <span className={`text-[10px] uppercase px-2 py-0.5 rounded border font-mono ${acc.badge}`}>
                    {acc.label}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </main>

      <footer className="px-6 py-3 border-t border-[#262626]/40 text-center text-[10px] font-mono text-[#737373] z-10">
        SECURED WITH HS256 JWT BEARER TOKENS · MULTI-TENANT POSTGRESQL · DETERMINISTIC ACCESS GATE
      </footer>
    </div>
  );
}
