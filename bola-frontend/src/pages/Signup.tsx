import { useState, type FormEvent } from 'react';
import logoImg from '../assets/logo.png';
import { signup, type SignupResult } from '../lib/api';

export default function Signup() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SignupResult | null>(null);
  const [copied, setCopied] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await signup(name.trim(), email.trim() || undefined);
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Signup failed');
    } finally {
      setLoading(false);
    }
  };

  const copyKey = async () => {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(result.api_key);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API unavailable (e.g. insecure context) - the key is still selectable text.
    }
  };

  return (
    <div className="cyber-grid-bg min-h-screen text-slate-200 font-sans flex items-center justify-center selection:bg-rose-900 selection:text-white antialiased">
      <div className="w-full max-w-md mx-4">
        <div className="border border-cyber-border/60 bg-cyber-panel/95 backdrop-blur-lg rounded-xl shadow-2xl p-8">
          <div className="text-center mb-8">
            <div className="inline-block mb-4">
              <img src={logoImg} alt="CyberAccess" className="h-12 w-12" />
            </div>
            <h1 className="text-2xl font-bold text-white mb-2">CyberAccess</h1>
            <p className="text-sm text-slate-400">BOLA Defense Platform</p>
          </div>

          {result ? (
            <>
              <div className="mb-6">
                <h2 className="text-xl font-semibold text-slate-100">You're all set</h2>
                <p className="text-sm text-slate-400 mt-1">
                  Tenant <span className="text-slate-200 font-semibold">{result.name}</span> created.
                </p>
              </div>

              <div className="px-4 py-3 bg-amber-900/20 border border-amber-500/30 rounded-lg mb-4">
                <p className="text-xs text-amber-300">
                  ⚠️ {result.warning}
                </p>
              </div>

              <label className="block text-xs font-semibold text-slate-300 mb-2 uppercase tracking-wide">
                Your API Key
              </label>
              <div className="flex gap-2 mb-6">
                <input
                  type="text"
                  readOnly
                  value={result.api_key}
                  onFocus={(e) => e.target.select()}
                  className="flex-1 min-w-0 px-4 py-2.5 bg-slate-900/50 border border-slate-700/50 rounded-lg text-slate-100 font-mono text-xs focus:outline-none focus:border-cyber-cyan/50"
                />
                <button
                  type="button"
                  onClick={copyKey}
                  className="px-4 py-2.5 bg-gradient-to-r from-cyber-cyan to-blue-500 hover:from-cyber-cyan/90 hover:to-blue-500/90 text-white font-semibold rounded-lg transition duration-200 text-sm whitespace-nowrap"
                >
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>

              <div className="p-3 bg-slate-900/50 border border-slate-700/30 rounded-lg text-xs text-slate-400 space-y-1">
                <p>Use it as the <code className="text-cyber-cyan">X-API-Key</code> header against <code className="text-cyber-cyan">/v1/authorize</code>, or as <code className="text-cyber-cyan">CYBERACCESS_API_KEY</code> with one of the SDKs.</p>
                <p className="pt-1">Tenant ID: <span className="text-slate-300 font-mono">{result.tenant_id}</span></p>
              </div>
            </>
          ) : (
            <>
              <div className="mb-6">
                <h2 className="text-xl font-semibold text-slate-100">Get an API key</h2>
                <p className="text-sm text-slate-400 mt-1">Create a tenant and get your key instantly - no approval needed.</p>
              </div>

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-2 uppercase tracking-wide">
                    Company / Project Name
                  </label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="acme-corp"
                    required
                    className="w-full px-4 py-2.5 bg-slate-900/50 border border-slate-700/50 rounded-lg text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyber-cyan/50 focus:ring-1 focus:ring-cyber-cyan/25 transition"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-2 uppercase tracking-wide">
                    Email <span className="text-slate-500 normal-case font-normal">(optional)</span>
                  </label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    className="w-full px-4 py-2.5 bg-slate-900/50 border border-slate-700/50 rounded-lg text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyber-cyan/50 focus:ring-1 focus:ring-cyber-cyan/25 transition"
                  />
                </div>

                {error && (
                  <div className="px-4 py-3 bg-rose-900/20 border border-rose-500/30 rounded-lg">
                    <p className="text-sm text-rose-300">{error}</p>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full mt-6 px-4 py-2.5 bg-gradient-to-r from-cyber-cyan to-blue-500 hover:from-cyber-cyan/90 hover:to-blue-500/90 disabled:from-slate-700 disabled:to-slate-700 disabled:opacity-50 text-white font-semibold rounded-lg transition duration-200 shadow-lg shadow-cyber-cyan/20"
                >
                  {loading ? 'Creating tenant...' : 'Get API Key'}
                </button>
              </form>

              <div className="mt-6 pt-6 border-t border-slate-700/30 text-center">
                <a href="/" className="text-xs text-cyber-cyan hover:underline">
                  Back to dashboard login
                </a>
              </div>
            </>
          )}
        </div>

        <div className="mt-8 text-center text-xs text-slate-500">
          <p>CyberAccess BOLA Defense Platform v1.1.1</p>
          <p className="mt-1">© 2026 Security Team. All rights reserved.</p>
        </div>
      </div>
    </div>
  );
}
