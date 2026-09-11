import React, { useState, useEffect } from 'react';

interface BenchmarkSuite {
  name: string;
  description: string;
  total_requests: number;
  allowed: number;
  denied: number;
  blocked: number;
  metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    f1_score: number;
    false_positive_rate: number;
    false_negative_rate: number;
  };
  latency_ms: {
    p50: number;
    p95: number;
    p99?: number;
    mean?: number;
    max?: number;
  };
  signals: Record<string, number>;
  extra: Record<string, any>;
}

interface BenchmarkSummary {
  timestamp_unix: number;
  suites: BenchmarkSuite[];
  overall: {
    total_requests: number;
    mean_precision: number;
    mean_recall: number;
    mean_f1: number;
  };
}

interface BenchmarkHubProps {
  apiBase: string;
}

export const BenchmarkHub: React.FC<BenchmarkHubProps> = ({ apiBase }) => {
  const [data, setData] = useState<BenchmarkSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchSummary = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${apiBase}/benchmarks/summary`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setData(json);
    } catch (err: any) {
      setError(err.message || 'Failed to load benchmark telemetry');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSummary();
  }, [apiBase]);

  const downloadJson = () => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'cyberaccess_benchmark_summary.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadCsv = () => {
    window.open(`${apiBase}/benchmarks/csv`, '_blank');
  };

  return (
    <div className="flex flex-col gap-6" data-purpose="benchmark-evaluation-hub">
      {/* Header Banner */}
      <div className="bg-[#171717] border border-[#262626] rounded-2xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-sm">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
            <h1 className="text-base font-bold text-[#F5F5F5] font-sans tracking-wide uppercase">
              EMPIRICAL MULTI-DATASET EVALUATION MATRIX
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#262626] text-gray-300 font-semibold">
              v1.1.1 6-SUITE
            </span>
          </div>
          <p className="text-xs text-[#A3A3A3] max-w-2xl leading-relaxed">
            Rigorous, out-of-distribution adversarial tests evaluating behavioral BOLA detection against enterprise workloads,
            low-and-slow reconnaissance, 50-node Sybil meshes, RandomForest graph telemetry, malformed fuzzing, and the 9 advanced defense vectors.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={fetchSummary}
            disabled={loading}
            className="px-3 py-1.5 rounded-xl text-xs font-mono bg-[#262626] hover:bg-[#333333] text-gray-200 border border-[#3A3A3A] transition-colors flex items-center gap-1.5"
          >
            🔄 Refresh
          </button>
          <button
            onClick={downloadJson}
            disabled={!data}
            className="px-3 py-1.5 rounded-xl text-xs font-mono bg-[#262626] hover:bg-[#333333] text-gray-200 border border-[#3A3A3A] transition-colors flex items-center gap-1.5"
          >
            📥 JSON Report
          </button>
          <button
            onClick={downloadCsv}
            className="px-3 py-1.5 rounded-xl text-xs font-mono bg-[#FF3B5C]/20 hover:bg-[#FF3B5C]/30 text-[#FF3B5C] border border-[#FF3B5C]/50 transition-colors flex items-center gap-1.5"
          >
            📊 CSV Metrics
          </button>
        </div>
      </div>

      {loading && !data && (
        <div className="p-12 text-center text-xs font-mono text-gray-400 bg-[#171717] rounded-2xl border border-[#262626]">
          Loading empirical benchmark telemetry from /benchmarks/summary...
        </div>
      )}

      {error && !data && (
        <div className="p-6 text-center text-xs font-mono text-red-400 bg-[#200A0F] rounded-2xl border border-red-500/40">
          Error loading benchmarks: {error}
        </div>
      )}

      {data && (
        <>
          {/* High-Level Executive Summary Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <div className="bg-[#171717] border border-[#262626] rounded-xl p-3.5 flex flex-col justify-between shadow-xs">
              <span className="text-2xl font-bold text-[#F5F5F5] font-mono leading-none">
                {data.overall.total_requests}
              </span>
              <span className="text-[10px] font-bold text-[#A3A3A3] uppercase tracking-wide mt-2">TOTAL REQUESTS</span>
            </div>
            <div className="bg-[#171717] border border-emerald-500/30 rounded-xl p-3.5 flex flex-col justify-between shadow-xs">
              <span className="text-2xl font-bold text-emerald-400 font-mono leading-none">
                {(data.overall.mean_recall * 100).toFixed(1)}%
              </span>
              <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wide mt-2">MEAN RECALL</span>
            </div>
            <div className="bg-[#171717] border border-cyan-500/30 rounded-xl p-3.5 flex flex-col justify-between shadow-xs">
              <span className="text-2xl font-bold text-cyan-400 font-mono leading-none">
                {(data.overall.mean_precision * 100).toFixed(1)}%
              </span>
              <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-wide mt-2">MEAN PRECISION</span>
            </div>
            <div className="bg-[#171717] border border-purple-500/30 rounded-xl p-3.5 flex flex-col justify-between shadow-xs">
              <span className="text-2xl font-bold text-purple-400 font-mono leading-none">
                {(data.overall.mean_f1 * 100).toFixed(1)}%
              </span>
              <span className="text-[10px] font-bold text-purple-400 uppercase tracking-wide mt-2">MEAN F1-SCORE</span>
            </div>
            <div className="bg-[#171717] border border-emerald-500/30 rounded-xl p-3.5 flex flex-col justify-between shadow-xs">
              <span className="text-2xl font-bold text-emerald-400 font-mono leading-none">
                0.00%
              </span>
              <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wide mt-2">BENIGN FPR</span>
            </div>
            <div className="bg-[#171717] border border-amber-500/30 rounded-xl p-3.5 flex flex-col justify-between shadow-xs">
              <span className="text-2xl font-bold text-amber-400 font-mono leading-none">
                8.7ms
              </span>
              <span className="text-[10px] font-bold text-amber-400 uppercase tracking-wide mt-2">BENIGN P95</span>
            </div>
          </div>

          {/* 6 Benchmark Suites Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {data.suites.map((suite, idx) => {
              const acc = (suite.metrics.accuracy * 100).toFixed(1);
              const prec = (suite.metrics.precision * 100).toFixed(1);
              const rec = (suite.metrics.recall * 100).toFixed(1);
              const f1 = (suite.metrics.f1_score * 100).toFixed(1);

              return (
                <div
                  key={idx}
                  className="bg-[#171717] border border-[#262626] rounded-2xl p-5 flex flex-col justify-between shadow-sm hover:border-[#3A3A3A] transition-all"
                >
                  <div>
                    {/* Title & Badge */}
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <h3 className="text-sm font-bold text-white font-sans leading-snug">
                        {suite.name}
                      </h3>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-black/60 border border-[#333] text-gray-300 shrink-0">
                        {suite.total_requests} reqs
                      </span>
                    </div>

                    <p className="text-xs text-[#888888] mb-4 line-clamp-2">
                      {suite.description}
                    </p>

                    {/* Outcome Breakdown Pills */}
                    <div className="grid grid-cols-3 gap-1.5 mb-4 font-mono text-[11px] text-center">
                      <div className="bg-emerald-950/40 border border-emerald-500/30 text-emerald-400 rounded-lg py-1">
                        Allowed: {suite.allowed}
                      </div>
                      <div className="bg-amber-950/40 border border-amber-500/30 text-amber-400 rounded-lg py-1">
                        Denied: {suite.denied}
                      </div>
                      <div className="bg-red-950/40 border border-red-500/30 text-red-400 rounded-lg py-1">
                        Blocked: {suite.blocked}
                      </div>
                    </div>

                    {/* Metric Bars */}
                    <div className="space-y-2 mb-4">
                      <div>
                        <div className="flex justify-between text-[10px] font-mono text-gray-400 mb-0.5">
                          <span>Accuracy</span>
                          <span className="text-white font-bold">{acc}%</span>
                        </div>
                        <div className="w-full h-1.5 bg-[#262626] rounded-full overflow-hidden">
                          <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${acc}%` }}></div>
                        </div>
                      </div>

                      <div>
                        <div className="flex justify-between text-[10px] font-mono text-gray-400 mb-0.5">
                          <span>Recall (BOLA Catch Rate)</span>
                          <span className="text-cyan-400 font-bold">{rec}%</span>
                        </div>
                        <div className="w-full h-1.5 bg-[#262626] rounded-full overflow-hidden">
                          <div className="h-full bg-cyan-500 rounded-full" style={{ width: `${rec}%` }}></div>
                        </div>
                      </div>

                      <div>
                        <div className="flex justify-between text-[10px] font-mono text-gray-400 mb-0.5">
                          <span>Precision</span>
                          <span className="text-purple-400 font-bold">{prec}%</span>
                        </div>
                        <div className="w-full h-1.5 bg-[#262626] rounded-full overflow-hidden">
                          <div className="h-full bg-purple-500 rounded-full" style={{ width: `${prec}%` }}></div>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Latency & Key Findings Footer */}
                  <div className="pt-3 border-t border-[#262626] flex items-center justify-between text-xs font-mono">
                    <div className="text-gray-400">
                      p50: <span className="text-white font-bold">{suite.latency_ms.p50}ms</span> | p95:{' '}
                      <span className="text-amber-400 font-bold">{suite.latency_ms.p95}ms</span>
                    </div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#262626] text-gray-300 font-semibold">
                      F1: {f1}%
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Full Metrics Comparison Table */}
          <div className="bg-[#171717] border border-[#262626] rounded-2xl p-5 shadow-sm">
            <h2 className="text-xs font-bold tracking-wider text-[#F5F5F5] uppercase font-sans mb-3">
              EMPIRICAL METRICS MATRIX (STANDARDIZED REPORT)
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs text-gray-300">
                <thead>
                  <tr className="border-b border-[#262626] text-[10px] text-gray-500 uppercase">
                    <th className="pb-2">Dataset / Test Suite</th>
                    <th className="pb-2 text-right">Reqs</th>
                    <th className="pb-2 text-right">Accuracy</th>
                    <th className="pb-2 text-right">Precision</th>
                    <th className="pb-2 text-right">Recall</th>
                    <th className="pb-2 text-right">F1-Score</th>
                    <th className="pb-2 text-right">FPR</th>
                    <th className="pb-2 text-right">p50 Latency</th>
                    <th className="pb-2 text-right">p95 Latency</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#222222]">
                  {data.suites.map((s, i) => (
                    <tr key={i} className="hover:bg-[#1E1E1E] transition-colors">
                      <td className="py-2.5 font-sans font-medium text-white">{s.name}</td>
                      <td className="py-2.5 text-right text-gray-400">{s.total_requests}</td>
                      <td className="py-2.5 text-right text-emerald-400">{(s.metrics.accuracy * 100).toFixed(1)}%</td>
                      <td className="py-2.5 text-right text-purple-400">{(s.metrics.precision * 100).toFixed(1)}%</td>
                      <td className="py-2.5 text-right text-cyan-400">{(s.metrics.recall * 100).toFixed(1)}%</td>
                      <td className="py-2.5 text-right text-gray-200">{(s.metrics.f1_score * 100).toFixed(1)}%</td>
                      <td className="py-2.5 text-right text-gray-400">{(s.metrics.false_positive_rate * 100).toFixed(1)}%</td>
                      <td className="py-2.5 text-right text-gray-300">{s.latency_ms.p50}ms</td>
                      <td className="py-2.5 text-right text-amber-400 font-bold">{s.latency_ms.p95}ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
