import { useState, FormEvent } from 'react';
import logoImg from '../assets/logo.png';
import { API_BASE } from '../lib/api';

interface LoginProps {
  onLoginSuccess: (token: string) => void;
}

export default function Login({ onLoginSuccess }: LoginProps) {
  const [subject, setSubject] = useState('security_admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject, password }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || 'Authentication failed');
      }

      const { access_token } = await res.json();
      onLoginSuccess(access_token);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="cyber-grid-bg min-h-screen text-slate-200 font-sans flex items-center justify-center selection:bg-rose-900 selection:text-white antialiased">
      <div className="w-full max-w-md mx-4">
        {/* Card Container */}
        <div className="border border-cyber-border/60 bg-cyber-panel/95 backdrop-blur-lg rounded-xl shadow-2xl p-8">
          {/* Logo & Branding */}
          <div className="text-center mb-8">
            <div className="inline-block mb-4">
              <img src={logoImg} alt="CyberAccess" className="h-12 w-12" />
            </div>
            <h1 className="text-2xl font-bold text-white mb-2">CyberAccess</h1>
            <p className="text-sm text-slate-400">BOLA Defense Platform</p>
          </div>

          {/* Heading */}
          <div className="mb-6">
            <h2 className="text-xl font-semibold text-slate-100">Security Dashboard</h2>
            <p className="text-sm text-slate-400 mt-1">Real-time threat intelligence and access control</p>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Subject/Username Field */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-2 uppercase tracking-wide">
                Subject / Admin ID
              </label>
              <input
                type="text"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="security_admin"
                className="w-full px-4 py-2.5 bg-slate-900/50 border border-slate-700/50 rounded-lg text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyber-cyan/50 focus:ring-1 focus:ring-cyber-cyan/25 transition"
              />
            </div>

            {/* Password Field */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-2 uppercase tracking-wide">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                className="w-full px-4 py-2.5 bg-slate-900/50 border border-slate-700/50 rounded-lg text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyber-cyan/50 focus:ring-1 focus:ring-cyber-cyan/25 transition"
              />
            </div>

            {/* Error Message */}
            {error && (
              <div className="px-4 py-3 bg-rose-900/20 border border-rose-500/30 rounded-lg">
                <p className="text-sm text-rose-300">{error}</p>
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full mt-6 px-4 py-2.5 bg-gradient-to-r from-cyber-cyan to-blue-500 hover:from-cyber-cyan/90 hover:to-blue-500/90 disabled:from-slate-700 disabled:to-slate-700 disabled:opacity-50 text-white font-semibold rounded-lg transition duration-200 shadow-lg shadow-cyber-cyan/20"
            >
              {loading ? 'Signing In...' : 'Sign In to Dashboard'}
            </button>
          </form>

          {/* Footer Info */}
          <div className="mt-6 pt-6 border-t border-slate-700/30">
            <p className="text-xs text-slate-500 text-center">
              Default: <span className="text-slate-300">security_admin</span> / <span className="text-slate-300">admin_changeme123</span>
            </p>
          </div>

          {/* Security Notice */}
          <div className="mt-4 p-3 bg-slate-900/50 border border-slate-700/30 rounded-lg">
            <p className="text-xs text-slate-400">
              <span className="font-semibold text-cyber-cyan">🔒 Secure Connection:</span> All data encrypted in transit. This dashboard monitors real-time BOLA attacks and access control decisions.
            </p>
          </div>
        </div>

        {/* Bottom Info */}
        <div className="mt-8 text-center text-xs text-slate-500">
          <p>CyberAccess BOLA Defense Platform v1.1.1</p>
          <p className="mt-1">© 2026 Security Team. All rights reserved.</p>
        </div>
      </div>
    </div>
  );
}
