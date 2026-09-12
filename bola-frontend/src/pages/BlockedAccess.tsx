interface BlockedAccessProps {
  subject?: string;
  decision?: string;
  score?: number;
  category?: string;
  signals?: string[];
  explanations?: string[];
  timestamp?: string;
  contactEmail?: string;
}

export default function BlockedAccess({
  subject = 'Unknown',
  decision = 'block',
  score = 85,
  category = 'Suspicious Activity',
  signals = [],
  explanations = ['Automated access detected'],
  timestamp = new Date().toISOString(),
  contactEmail = 'security@company.com',
}: BlockedAccessProps) {
  const isBlock = decision === 'block';
  const isDeny = decision === 'deny';

  const signalLabels: Record<string, string> = {
    rapid_enumeration: '🔍 Object Enumeration',
    rapid_requests: '⚡ Rapid Requests',
    auth_velocity: '🚀 Authentication Velocity',
    unusual_timing: '⏱️ Unusual Timing',
    ip_reputation: '🌐 IP Reputation',
    pattern_match: '🎯 Attack Pattern',
    canary_honeypot_triggered: '🚨 Honeypot Triggered',
    temporary_lockout: '🔒 Temporary Lockout',
    3_strike_ban: '⛔ 3-Strike Policy',
  };

  return (
    <div className="cyber-grid-bg min-h-screen text-slate-200 font-sans flex items-center justify-center selection:bg-rose-900 selection:text-white antialiased p-4">
      <div className="w-full max-w-2xl">
        {/* Main Card */}
        <div
          className={`border rounded-xl shadow-2xl backdrop-blur-lg p-8 ${
            isBlock
              ? 'bg-rose-900/10 border-rose-500/40'
              : 'bg-amber-900/10 border-amber-500/40'
          }`}
        >
          {/* Header with Icon */}
          <div className="text-center mb-8">
            <div
              className={`inline-flex items-center justify-center w-20 h-20 rounded-full mb-4 ${
                isBlock
                  ? 'bg-rose-500/20 border border-rose-500/40'
                  : 'bg-amber-500/20 border border-amber-500/40'
              }`}
            >
              <span className="text-5xl">{isBlock ? '🚫' : '⚠️'}</span>
            </div>

            <h1
              className={`text-3xl font-bold mb-2 ${
                isBlock ? 'text-rose-300' : 'text-amber-300'
              }`}
            >
              {isBlock ? 'Access Blocked' : 'Access Denied'}
            </h1>

            <p className="text-slate-400">
              Your request has been blocked by our security system
            </p>
          </div>

          {/* Status Bar */}
          <div className="grid grid-cols-2 gap-4 mb-8">
            <div className="bg-slate-900/50 border border-slate-700/30 rounded-lg p-4">
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">
                Risk Score
              </p>
              <p className={`text-2xl font-bold ${
                score > 70 ? 'text-rose-400' : score > 40 ? 'text-amber-400' : 'text-emerald-400'
              }`}>
                {score.toFixed(0)}/100
              </p>
            </div>

            <div className="bg-slate-900/50 border border-slate-700/30 rounded-lg p-4">
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">
                Category
              </p>
              <p className="text-lg font-semibold text-slate-200">{category}</p>
            </div>
          </div>

          {/* Detected Signals */}
          {signals.length > 0 && (
            <div className="mb-8">
              <h3 className="text-sm font-semibold text-slate-300 mb-3 uppercase tracking-wide">
                Detected Signals
              </h3>
              <div className="space-y-2">
                {signals.map((signal, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-2 px-3 py-2 bg-slate-900/30 border border-slate-700/20 rounded-lg"
                  >
                    <span className="text-xs font-semibold text-slate-400">
                      {signalLabels[signal] || signal}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Explanations */}
          {explanations.length > 0 && (
            <div className="mb-8">
              <h3 className="text-sm font-semibold text-slate-300 mb-3 uppercase tracking-wide">
                Reason
              </h3>
              <div className={`px-4 py-3 rounded-lg border ${
                isBlock
                  ? 'bg-rose-900/20 border-rose-500/30'
                  : 'bg-amber-900/20 border-amber-500/30'
              }`}>
                <ul className="space-y-2">
                  {explanations.map((exp, idx) => (
                    <li key={idx} className="text-sm text-slate-300 flex items-start gap-2">
                      <span className="text-lg mt-0.5">•</span>
                      <span>{exp}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {/* Subject & Timestamp (if available) */}
          <div className="grid grid-cols-2 gap-4 mb-8 text-xs">
            <div className="bg-slate-900/50 border border-slate-700/30 rounded p-3">
              <p className="text-slate-500 uppercase tracking-wide mb-1">Subject</p>
              <p className="text-slate-200 font-mono">{subject}</p>
            </div>
            <div className="bg-slate-900/50 border border-slate-700/30 rounded p-3">
              <p className="text-slate-500 uppercase tracking-wide mb-1">Timestamp</p>
              <p className="text-slate-200 font-mono">
                {new Date(timestamp).toLocaleString()}
              </p>
            </div>
          </div>

          {/* What You Can Do */}
          <div className="bg-slate-900/30 border border-slate-700/20 rounded-lg p-4 mb-8">
            <h4 className="text-sm font-semibold text-slate-300 mb-3">What to Do Next:</h4>
            <ol className="space-y-2 text-sm text-slate-400">
              <li className="flex items-start gap-2">
                <span className="font-semibold text-slate-300 min-w-fit">1.</span>
                <span>Review the detected signals above — they indicate suspicious behavior patterns</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="font-semibold text-slate-300 min-w-fit">2.</span>
                <span>
                  If you believe this is a false positive, contact our security team at{' '}
                  <span className="text-cyber-cyan font-mono">{contactEmail}</span>
                </span>
              </li>
              <li className="flex items-start gap-2">
                <span className="font-semibold text-slate-300 min-w-fit">3.</span>
                <span>
                  {isBlock
                    ? 'Your access has been temporarily blocked. Try again in a few minutes.'
                    : 'You are not authorized to access this resource. Contact your administrator.'}
                </span>
              </li>
              <li className="flex items-start gap-2">
                <span className="font-semibold text-slate-300 min-w-fit">4.</span>
                <span>
                  For security incidents, provide this reference ID to our support team
                </span>
              </li>
            </ol>
          </div>

          {/* Security Notice */}
          <div className="bg-gradient-to-r from-slate-900/50 to-slate-800/30 border border-slate-700/30 rounded-lg p-4">
            <p className="text-xs text-slate-400 leading-relaxed">
              <span className="font-semibold text-slate-300">🔐 About CyberAccess BOLA Defense:</span> This action was
              taken by our automated security system to protect against Broken Object Level Authorization (BOLA) attacks and
              other unauthorized access attempts. Your behavior was flagged by our machine learning models as potentially
              malicious. This is not a permanent ban — most blocks expire automatically after a short time.
            </p>
          </div>
        </div>

        {/* Footer Links */}
        <div className="mt-8 text-center">
          <div className="space-y-2 text-sm text-slate-500">
            <p>
              <a href="/" className="text-cyber-cyan hover:text-cyan-300 transition">
                ← Return Home
              </a>
            </p>
            <p>
              <a href={`mailto:${contactEmail}`} className="text-cyber-cyan hover:text-cyan-300 transition">
                Contact Support
              </a>
            </p>
            <p className="text-xs text-slate-600 mt-4">
              CyberAccess BOLA Defense Platform v1.1.1 | Status: Protected
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
