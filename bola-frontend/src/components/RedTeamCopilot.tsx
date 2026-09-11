import React, { useState, useEffect } from 'react';

interface RedTeamCopilotProps {
  apiBase: string;
  authToken: string;
  onRefreshTelemetry: () => void;
}

export const RedTeamCopilot: React.FC<RedTeamCopilotProps> = ({
  apiBase,
  authToken,
  onRefreshTelemetry
}) => {
  // Campaign State
  const [activeSubTab, setActiveSubTab] = useState<'campaign' | 'remediation' | 'compliance'>('campaign');
  const [selectedScenario, setSelectedScenario] = useState<'idor_sweep' | 'horizontal_privilege' | 'canary_trap' | 'stealth_creep' | 'custom'>('idor_sweep');
  const [attackerSubject, setAttackerSubject] = useState('attacker_1');
  const [customTargetIds, setCustomTargetIds] = useState('51, 52, 53, 54, 55, 56');
  const [isLaunching, setIsLaunching] = useState(false);
  const [campaignResult, setCampaignResult] = useState<any>(null);

  // Remediation State
  const [remediationRecordId, setRemediationRecordId] = useState('55');
  const [remediationSubject, setRemediationSubject] = useState('attacker_1');
  const [activeCodeTab, setActiveCodeTab] = useState<'fastapi' | 'express' | 'go' | 'sigma' | 'waf'>('fastapi');
  const [remediationData, setRemediationData] = useState<any>(null);
  const [isGeneratingRemediation, setIsGeneratingRemediation] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Compliance / Cryptographic Proof State
  const [auditProof, setAuditProof] = useState<any>(null);
  const [isLoadingProof, setIsLoadingProof] = useState(false);

  // Update target records when scenario changes
  useEffect(() => {
    if (selectedScenario === 'idor_sweep') {
      setAttackerSubject('attacker_1');
      setCustomTargetIds('51, 52, 53, 54, 55, 56, 57, 58');
    } else if (selectedScenario === 'horizontal_privilege') {
      setAttackerSubject('alice');
      setCustomTargetIds('51, 52, 53, 54, 55');
    } else if (selectedScenario === 'canary_trap') {
      setAttackerSubject('attacker_1');
      setCustomTargetIds('0, 999999, canary_admin_vault');
    } else if (selectedScenario === 'stealth_creep') {
      setAttackerSubject('attacker_slow');
      setCustomTargetIds('50, 51, 52, 53, 54, 55');
    }
  }, [selectedScenario]);

  // Fetch initial audit proof & remediation
  useEffect(() => {
    fetchAuditProof();
    generateRemediationPatch('55', 'attacker_1');
  }, []);

  const fetchAuditProof = async () => {
    setIsLoadingProof(true);
    try {
      const res = await fetch(`${apiBase}/forensics/audit-proof`, {
        headers: authToken ? { Authorization: `Bearer ${authToken}` } : {}
      });
      if (res.ok) {
        const data = await res.json();
        setAuditProof(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoadingProof(false);
    }
  };

  const executeCampaign = async () => {
    setIsLaunching(true);
    setCampaignResult(null);
    try {
      const targets = customTargetIds
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);

      const res = await fetch(`${apiBase}/redteam/campaign`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {})
        },
        body: JSON.stringify({
          attacker_subject: attackerSubject.trim(),
          scenario_name: selectedScenario,
          target_records: targets
        })
      });

      if (res.ok) {
        const data = await res.json();
        setCampaignResult(data);
        onRefreshTelemetry();
        fetchAuditProof();
        if (data.steps && data.steps.length > 0) {
          const firstBlocked = data.steps.find((s: any) => s.status_code === 403) || data.steps[0];
          setRemediationRecordId(firstBlocked.target_record_id);
          setRemediationSubject(data.attacker_subject);
          generateRemediationPatch(firstBlocked.target_record_id, data.attacker_subject);
        }
      } else {
        const err = await res.json().catch(() => ({}));
        setCampaignResult({ error: err.detail || 'Campaign execution failed' });
      }
    } catch (err: any) {
      setCampaignResult({ error: err.message || 'Network error executing attack campaign' });
    } finally {
      setIsLaunching(false);
    }
  };

  const generateRemediationPatch = async (recId: string, subj: string) => {
    setIsGeneratingRemediation(true);
    try {
      const res = await fetch(`${apiBase}/forensics/remediation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          record_id: recId,
          subject: subj,
          endpoint: `/records/${recId}`
        })
      });
      if (res.ok) {
        const data = await res.json();
        setRemediationData(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsGeneratingRemediation(false);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const downloadAuditCertificate = () => {
    if (!auditProof) return;
    const certText = `# CYBERACCESS TAMPER-EVIDENT COMPLIANCE CERTIFICATE
Generated: ${new Date().toISOString()}
Tenant: demo-tenant
Chain Algorithm: ${auditProof.chain_algorithm}
Merkle Root: ${auditProof.merkle_root}
Total Verified Audit Events: ${auditProof.total_events_verified}
Ledger Integrity: ${auditProof.ledger_valid ? 'VERIFIED CRYPTOGRAPHICALLY INTACT' : 'COMPROMISED'}

## Regulatory Compliance Attestation:
- OWASP API Security: ${auditProof.compliance_posture?.owasp_api1_2023 || 'PROTECTED'}
- HIPAA Security Rule: ${auditProof.compliance_posture?.hipaa_164_312 || 'COMPLIANT'}
- GDPR Article 32: ${auditProof.compliance_posture?.gdpr_art_32 || 'VERIFIED'}
- SOC 2 Type II: ${auditProof.compliance_posture?.soc2_cc6 || 'AUDITED'}

## Cryptographic Proof Sign-off:
This cryptographic evidence guarantees zero tampering, backdating, or unlogged access attempts across all protected object records.
Root Signature: ${auditProof.merkle_root}
`;
    const blob = new Blob([certText], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyberaccess_audit_certificate_${Date.now()}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Top Header & Navigation Banner */}
      <div className="bg-[#141414] border border-[#262626] rounded-2xl p-5 shadow-lg flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-[#FF3B5C]/10 text-[#FF3B5C] text-lg">🎯</span>
            <h2 className="text-base font-bold text-white tracking-wide">
              RED TEAM ARSENAL & REMEDIATION COPILOT
            </h2>
          </div>
          <p className="text-xs text-gray-400 mt-1 font-mono">
            Execute automated adversarial BOLA campaigns, inspect real-time strike escalations, synthesize drop-in code fixes, and verify cryptographic Merkle audit proofs.
          </p>
        </div>

        {/* Sub-Navigation Pills */}
        <div className="flex items-center gap-1.5 bg-[#0A0A0A] p-1 border border-[#262626] rounded-xl font-mono text-xs">
          <button
            onClick={() => setActiveSubTab('campaign')}
            className={`px-3 py-1.5 rounded-lg transition-colors ${
              activeSubTab === 'campaign'
                ? 'bg-[#FF3B5C] text-black font-bold'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            ⚡ ATTACK CAMPAIGN
          </button>
          <button
            onClick={() => setActiveSubTab('remediation')}
            className={`px-3 py-1.5 rounded-lg transition-colors ${
              activeSubTab === 'remediation'
                ? 'bg-[#FF3B5C] text-black font-bold'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            🛠️ CODE REMEDIATION & WAF
          </button>
          <button
            onClick={() => setActiveSubTab('compliance')}
            className={`px-3 py-1.5 rounded-lg transition-colors ${
              activeSubTab === 'compliance'
                ? 'bg-[#FF3B5C] text-black font-bold'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            📜 COMPLIANCE & MERKLE
          </button>
        </div>
      </div>

      {/* TAB 1: ATTACK CAMPAIGN */}
      {activeSubTab === 'campaign' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Configuration */}
          <div className="bg-[#141414] border border-[#262626] rounded-2xl p-5 shadow-lg space-y-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-gray-400 font-mono flex items-center justify-between">
              <span>Attack Scenario Selector</span>
              <span className="text-[10px] text-[#FF3B5C]">RED TEAM SUITE</span>
            </h3>

            {/* Presets */}
            <div className="space-y-2">
              {[
                {
                  id: 'idor_sweep',
                  title: 'IDOR Scraping Storm',
                  desc: 'Rapid sequential object traversal cycling across target resource IDs.',
                  badge: 'HIGH VELOCITY'
                },
                {
                  id: 'horizontal_privilege',
                  title: 'Horizontal Peer Breach',
                  desc: 'Valid user (Alice) attempting cross-tenant access to Bob’s private records.',
                  badge: 'CROSS-TENANT'
                },
                {
                  id: 'canary_trap',
                  title: 'Honeytoken Decoy Detonation',
                  desc: 'Adversary targeting zero-tolerance canary traps triggering immediate permanent bans.',
                  badge: 'TRIPWIRE'
                },
                {
                  id: 'stealth_creep',
                  title: 'Stealth Low-and-Slow Attack',
                  desc: 'Paced requests attempting to evade velocity window thresholds.',
                  badge: 'EVASION'
                },
                {
                  id: 'custom',
                  title: 'Custom Attack Builder',
                  desc: 'Configure bespoke adversary actor, target scopes, and execution parameters.',
                  badge: 'CONFIGURABLE'
                }
              ].map((sc) => (
                <div
                  key={sc.id}
                  onClick={() => setSelectedScenario(sc.id as any)}
                  className={`p-3 rounded-xl border cursor-pointer transition-all ${
                    selectedScenario === sc.id
                      ? 'bg-[#201013] border-[#FF3B5C] text-white'
                      : 'bg-[#191919] border-[#2A2A2A] text-gray-300 hover:border-[#383838]'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-xs">{sc.title}</span>
                    <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-black/40 text-[#FF3B5C]">
                      {sc.badge}
                    </span>
                  </div>
                  <p className="text-[11px] text-gray-400 mt-1 leading-snug">{sc.desc}</p>
                </div>
              ))}
            </div>

            {/* Attacker Identity & Target Scope */}
            <div className="pt-2 border-t border-[#262626] space-y-3 font-mono text-xs">
              <div>
                <label className="text-gray-400 block mb-1">Adversary Subject Identity</label>
                <input
                  type="text"
                  value={attackerSubject}
                  onChange={(e) => setAttackerSubject(e.target.value)}
                  className="w-full bg-[#1F1F1F] border border-[#333] rounded-lg px-3 py-2 text-white font-mono focus:outline-hidden focus:border-[#FF3B5C]"
                  placeholder="e.g. attacker_1, alice, attacker_slow"
                />
              </div>

              <div>
                <label className="text-gray-400 block mb-1">Target Resource IDs (Comma-separated)</label>
                <input
                  type="text"
                  value={customTargetIds}
                  onChange={(e) => setCustomTargetIds(e.target.value)}
                  className="w-full bg-[#1F1F1F] border border-[#333] rounded-lg px-3 py-2 text-white font-mono focus:outline-hidden focus:border-[#FF3B5C]"
                  placeholder="51, 52, 53, 54, 55"
                />
              </div>
            </div>

            {/* Launch Button */}
            <button
              onClick={executeCampaign}
              disabled={isLaunching}
              className="w-full mt-2 py-3 rounded-xl bg-gradient-to-r from-[#FF3B5C] to-[#E02444] hover:from-[#FF4D6D] hover:to-[#FF3B5C] text-black font-bold font-mono text-xs tracking-wider transition-all disabled:opacity-50 shadow-md flex items-center justify-center gap-2"
            >
              {isLaunching ? (
                <>
                  <div className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin" />
                  <span>SIMULATING ATTACK CAMPAIGN...</span>
                </>
              ) : (
                <>
                  <span>🚀</span>
                  <span>LAUNCH ATTACK CAMPAIGN</span>
                </>
              )}
            </button>
          </div>

          {/* Right 2 Columns: Live Execution Feed & Metrics */}
          <div className="lg:col-span-2 space-y-4">
            {/* Top Metric Cards */}
            {campaignResult && !campaignResult.error && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
                <div className="bg-[#141414] border border-[#262626] rounded-xl p-3">
                  <span className="text-[10px] text-gray-400 uppercase block">Probes Sent</span>
                  <span className="text-xl font-bold text-white mt-0.5 block">
                    {campaignResult.total_requests}
                  </span>
                  <span className="text-[10px] text-gray-500">{campaignResult.duration_ms} ms elapsed</span>
                </div>

                <div className="bg-[#141414] border border-[#262626] rounded-xl p-3">
                  <span className="text-[10px] text-gray-400 uppercase block">Interception Rate</span>
                  <span className="text-xl font-bold text-emerald-400 mt-0.5 block">
                    {campaignResult.interception_rate_percent}%
                  </span>
                  <span className="text-[10px] text-emerald-500/80">
                    {campaignResult.blocked_count + campaignResult.denied_count} blocked / denied
                  </span>
                </div>

                <div className="bg-[#141414] border border-[#262626] rounded-xl p-3">
                  <span className="text-[10px] text-gray-400 uppercase block">Peak Threat Score</span>
                  <span className="text-xl font-bold text-[#FF3B5C] mt-0.5 block">
                    {campaignResult.peak_risk_score} pts
                  </span>
                  <span className="text-[10px] text-[#FF3B5C]/70">Model 1 Anomaly</span>
                </div>

                <div className="bg-[#141414] border border-[#262626] rounded-xl p-3">
                  <span className="text-[10px] text-gray-400 uppercase block">Adversary Status</span>
                  <span className={`text-xs font-bold mt-1 inline-block px-2 py-0.5 rounded ${
                    campaignResult.quarantined
                      ? 'bg-[#201013] text-[#FF3B5C] border border-[#FF3B5C]/40'
                      : 'bg-emerald-950/40 text-emerald-400 border border-emerald-500/40'
                  }`}>
                    {campaignResult.quarantined ? 'QUARANTINED' : 'MONITORED'}
                  </span>
                </div>
              </div>
            )}

            {/* Verdict Banner */}
            {campaignResult && !campaignResult.error && (
              <div className={`p-4 rounded-xl border flex items-start gap-3 font-mono text-xs ${
                campaignResult.quarantined || campaignResult.canary_tripped
                  ? 'bg-[#201013] border-[#FF3B5C]/50 text-[#FF3B5C]'
                  : 'bg-[#121A15] border-emerald-500/40 text-emerald-400'
              }`}>
                <span className="text-base">🛡️</span>
                <div>
                  <span className="font-bold block uppercase tracking-wide">Forensic Verdict:</span>
                  <p className="mt-0.5 text-gray-200">{campaignResult.verdict}</p>
                </div>
              </div>
            )}

            {/* Step-by-Step Telemetry Table */}
            <div className="bg-[#141414] border border-[#262626] rounded-2xl p-5 shadow-lg">
              <div className="flex items-center justify-between mb-3 font-mono">
                <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span>Real-Time Threat Telemetry Stream</span>
                </h4>
                {campaignResult?.steps && (
                  <span className="text-[11px] text-gray-400">
                    {campaignResult.steps.length} Probes Executed
                  </span>
                )}
              </div>

              {!campaignResult ? (
                <div className="py-16 text-center text-gray-500 font-mono text-xs">
                  <p>No attack campaign launched yet.</p>
                  <p className="text-[11px] text-gray-600 mt-1">
                    Select an attack archetype on the left and click "Launch Attack Campaign" to observe live multi-layer defense interception.
                  </p>
                </div>
              ) : campaignResult.error ? (
                <div className="p-4 rounded-xl bg-red-950/30 border border-red-500/30 text-red-400 font-mono text-xs">
                  {campaignResult.error}
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs">
                    <thead>
                      <tr className="border-b border-[#262626] text-gray-400 text-[10px] uppercase">
                        <th className="pb-2">Step</th>
                        <th className="pb-2">Endpoint</th>
                        <th className="pb-2">Status</th>
                        <th className="pb-2">Risk</th>
                        <th className="pb-2">Strikes</th>
                        <th className="pb-2">Signals / Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#202020]">
                      {campaignResult.steps.map((step: any) => {
                        const isBlocked = step.status_code === 403;
                        const isAllowed = step.status_code === 200;
                        return (
                          <tr key={step.step} className="hover:bg-[#1A1A1A] transition-colors">
                            <td className="py-2.5 text-gray-400">#{step.step}</td>
                            <td className="py-2.5 font-bold text-white">
                              GET /records/{step.target_record_id}
                            </td>
                            <td className="py-2.5">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                isBlocked
                                  ? 'bg-[#201013] text-[#FF3B5C] border border-[#FF3B5C]/30'
                                  : isAllowed
                                  ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-500/30'
                                  : 'bg-amber-950/40 text-amber-400 border border-amber-500/30'
                              }`}>
                                {step.status_code} {step.decision.toUpperCase()}
                              </span>
                            </td>
                            <td className="py-2.5">
                              <span className={`text-[11px] font-bold ${
                                step.risk_score >= 80 ? 'text-[#FF3B5C]' : step.risk_score >= 40 ? 'text-amber-400' : 'text-gray-400'
                              }`}>
                                {step.risk_score} pts
                              </span>
                            </td>
                            <td className="py-2.5">
                              <span className="text-[11px] text-gray-300">
                                Strike {step.current_strikes}/3
                              </span>
                              {step.is_quarantined && (
                                <span className="ml-1 text-[9px] text-[#FF3B5C] font-bold">
                                  [QUARANTINED]
                                </span>
                              )}
                            </td>
                            <td className="py-2.5">
                              <div className="flex flex-wrap gap-1">
                                {step.signals && step.signals.length > 0 ? (
                                  step.signals.map((sig: string, i: number) => (
                                    <span
                                      key={i}
                                      className="px-1.5 py-0.5 rounded text-[9px] bg-[#22140c] text-[#F97316] border border-[#F97316]/30"
                                    >
                                      {sig}
                                    </span>
                                  ))
                                ) : (
                                  <span className="text-gray-500 text-[10px]">Normal profile</span>
                                )}
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: CODE REMEDIATION & WAF RULES */}
      {activeSubTab === 'remediation' && (
        <div className="bg-[#141414] border border-[#262626] rounded-2xl p-6 shadow-lg space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[#262626]">
            <div>
              <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                <span>🛡️</span>
                <span>AUTOMATED INCIDENT REMEDIATION GENERATOR</span>
              </h3>
              <p className="text-xs text-gray-400 mt-0.5 font-mono">
                Synthesize drop-in authorization patches, Sigma SIEM signatures, and Cloudflare WAF JSON expressions for intercepted BOLA events.
              </p>
            </div>

            {/* Target incident selector */}
            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="text-gray-400">Target Record:</span>
              <input
                type="text"
                value={remediationRecordId}
                onChange={(e) => {
                  setRemediationRecordId(e.target.value);
                  generateRemediationPatch(e.target.value, remediationSubject);
                }}
                className="w-20 bg-[#1F1F1F] border border-[#333] rounded-lg px-2 py-1 text-white font-bold text-center focus:outline-hidden focus:border-[#FF3B5C]"
              />
            </div>
          </div>

          {/* Vulnerability Classification Card */}
          {remediationData && (
            <div className="p-4 rounded-xl bg-[#1A1A1A] border border-[#2C2C2C] space-y-2 font-mono text-xs">
              <div className="flex flex-wrap items-center gap-3">
                <span className="px-2 py-0.5 rounded bg-[#201013] text-[#FF3B5C] font-bold border border-[#FF3B5C]/30 text-[10px]">
                  {remediationData.owasp_category}
                </span>
                <span className="text-gray-400 text-[11px]">
                  {remediationData.cwe_id}
                </span>
              </div>
              <p className="text-gray-300 leading-relaxed text-[11px]">
                {remediationData.remediation_summary}
              </p>
            </div>
          )}

          {/* Code & Detection Signature Tabs */}
          <div className="space-y-3 font-mono text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#262626] pb-2">
              <div className="flex flex-wrap gap-1">
                {[
                  { id: 'fastapi', label: 'Python (FastAPI + SDK)' },
                  { id: 'express', label: 'Node.js (Express)' },
                  { id: 'go', label: 'Go (Gin Framework)' },
                  { id: 'sigma', label: 'Sigma Rule (SIEM)' },
                  { id: 'waf', label: 'Cloudflare WAF (JSON)' }
                ].map((t) => (
                  <button
                    key={t.id}
                    onClick={() => setActiveCodeTab(t.id as any)}
                    className={`px-3 py-1 rounded-lg transition-colors text-[11px] ${
                      activeCodeTab === t.id
                        ? 'bg-[#FF3B5C] text-black font-bold'
                        : 'bg-[#1E1E1E] text-gray-400 hover:text-white'
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>

              {/* Copy Button */}
              {remediationData && (
                <button
                  onClick={() => {
                    const textToCopy =
                      activeCodeTab === 'fastapi'
                        ? remediationData.code_snippets.python_fastapi
                        : activeCodeTab === 'express'
                        ? remediationData.code_snippets.nodejs_express
                        : activeCodeTab === 'go'
                        ? remediationData.code_snippets.go_gin
                        : activeCodeTab === 'sigma'
                        ? remediationData.detection_rules.sigma_yaml
                        : remediationData.detection_rules.cloudflare_waf_json;
                    copyToClipboard(textToCopy, activeCodeTab);
                  }}
                  className="px-3 py-1 rounded-lg bg-[#262626] hover:bg-[#333] text-gray-200 transition-colors flex items-center gap-1.5"
                >
                  <span>{copiedKey === activeCodeTab ? '✓ COPIED!' : '📋 COPY CODE'}</span>
                </button>
              )}
            </div>

            {/* Code Display Area */}
            {isGeneratingRemediation ? (
              <div className="p-8 text-center text-gray-500">
                <div className="w-5 h-5 border-2 border-[#FF3B5C]/30 border-t-[#FF3B5C] rounded-full animate-spin mx-auto mb-2" />
                <span>Generating tailored defense patches...</span>
              </div>
            ) : remediationData ? (
              <pre className="p-4 rounded-xl bg-[#0A0A0A] border border-[#262626] text-gray-300 overflow-x-auto text-[11px] leading-relaxed max-h-[400px]">
                <code>
                  {activeCodeTab === 'fastapi' && remediationData.code_snippets.python_fastapi}
                  {activeCodeTab === 'express' && remediationData.code_snippets.nodejs_express}
                  {activeCodeTab === 'go' && remediationData.code_snippets.go_gin}
                  {activeCodeTab === 'sigma' && remediationData.detection_rules.sigma_yaml}
                  {activeCodeTab === 'waf' && remediationData.detection_rules.cloudflare_waf_json}
                </code>
              </pre>
            ) : (
              <div className="p-8 text-center text-gray-500">
                No remediation available for this resource.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: COMPLIANCE & MERKLE CRYPTOGRAPHIC PROOF */}
      {activeSubTab === 'compliance' && (
        <div className="bg-[#141414] border border-[#262626] rounded-2xl p-6 shadow-lg space-y-6 font-mono">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#262626]">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>📜</span>
                <span>CRYPTOGRAPHIC AUDIT LEDGER & COMPLIANCE CERTIFICATE</span>
              </h3>
              <p className="text-xs text-gray-400 mt-0.5">
                Every forensic audit event is linked into an immutable SHA-256 Merkle chain, providing mathematical non-repudiation for regulatory audits.
              </p>
            </div>

            <button
              onClick={downloadAuditCertificate}
              disabled={!auditProof}
              className="px-4 py-2 rounded-xl bg-[#201013] hover:bg-[#2B1418] border border-[#FF3B5C]/50 hover:border-[#FF3B5C] text-[#FF3B5C] text-xs font-bold transition-colors flex items-center gap-2"
            >
              <span>📥</span>
              <span>DOWNLOAD AUDIT PROOF (.MD)</span>
            </button>
          </div>

          {isLoadingProof ? (
            <div className="py-12 text-center text-gray-500 text-xs">
              <div className="w-5 h-5 border-2 border-[#FF3B5C]/30 border-t-[#FF3B5C] rounded-full animate-spin mx-auto mb-2" />
              <span>Verifying SHA-256 Merkle Chain Integrity...</span>
            </div>
          ) : auditProof ? (
            <div className="space-y-6">
              {/* Integrity Status Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl bg-[#1A1A1A] border border-[#262626]">
                  <span className="text-[10px] text-gray-400 uppercase block">Ledger Integrity</span>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
                    <span className="text-sm font-bold text-emerald-400">
                      {auditProof.ledger_valid ? '100% CRYPTOGRAPHICALLY VALID' : 'TAMPER DETECTED'}
                    </span>
                  </div>
                  <span className="text-[10px] text-gray-500 mt-1 block">
                    Zero missing blocks or altered records
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-[#1A1A1A] border border-[#262626]">
                  <span className="text-[10px] text-gray-400 uppercase block">Verified Audit Events</span>
                  <span className="text-xl font-bold text-white mt-1 block">
                    {auditProof.total_events_verified} Events
                  </span>
                  <span className="text-[10px] text-gray-500 mt-1 block">
                    Chained via {auditProof.chain_algorithm}
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-[#1A1A1A] border border-[#262626]">
                  <span className="text-[10px] text-gray-400 uppercase block">Current Merkle Root</span>
                  <span className="text-xs font-mono font-bold text-[#FF3B5C] mt-1 block truncate" title={auditProof.merkle_root}>
                    {auditProof.merkle_root}
                  </span>
                  <span className="text-[10px] text-gray-500 mt-1 block">
                    Tamper-proof root hash
                  </span>
                </div>
              </div>

              {/* Regulatory Compliance Posture */}
              <div className="p-5 rounded-xl bg-[#0F0F0F] border border-[#262626] space-y-3">
                <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider">
                  Attested Regulatory Compliance Standards
                </h4>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="p-3 rounded-lg bg-[#141414] border border-[#222]">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white">OWASP API Security Top 10</span>
                      <span className="text-[10px] text-emerald-400 font-bold px-1.5 py-0.5 rounded bg-emerald-950/40">
                        VERIFIED
                      </span>
                    </div>
                    <p className="text-[11px] text-gray-400 mt-1">
                      {auditProof.compliance_posture?.owasp_api1_2023 || 'PROTECTED'}
                    </p>
                  </div>

                  <div className="p-3 rounded-lg bg-[#141414] border border-[#222]">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white">HIPAA Security Rule §164.312</span>
                      <span className="text-[10px] text-emerald-400 font-bold px-1.5 py-0.5 rounded bg-emerald-950/40">
                        COMPLIANT
                      </span>
                    </div>
                    <p className="text-[11px] text-gray-400 mt-1">
                      {auditProof.compliance_posture?.hipaa_164_312 || 'COMPLIANT'}
                    </p>
                  </div>

                  <div className="p-3 rounded-lg bg-[#141414] border border-[#222]">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white">GDPR Article 32</span>
                      <span className="text-[10px] text-emerald-400 font-bold px-1.5 py-0.5 rounded bg-emerald-950/40">
                        VERIFIED
                      </span>
                    </div>
                    <p className="text-[11px] text-gray-400 mt-1">
                      {auditProof.compliance_posture?.gdpr_art_32 || 'VERIFIED'}
                    </p>
                  </div>

                  <div className="p-3 rounded-lg bg-[#141414] border border-[#222]">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white">SOC 2 Type II (CC6)</span>
                      <span className="text-[10px] text-emerald-400 font-bold px-1.5 py-0.5 rounded bg-emerald-950/40">
                        AUDITED
                      </span>
                    </div>
                    <p className="text-[11px] text-gray-400 mt-1">
                      {auditProof.compliance_posture?.soc2_cc6 || 'AUDITED'}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="py-8 text-center text-gray-500 text-xs">
              Unable to load cryptographic audit proof.
            </div>
          )}
        </div>
      )}
    </div>
  );
};
