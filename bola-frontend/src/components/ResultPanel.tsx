export function StatusPill({ status, outcome }: { status: number; outcome: string }) {
  const ok = outcome === 'allowed';
  return (
    <span
      className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full font-mono text-xs font-bold"
      style={{
        backgroundColor: ok ? '#052e22' : '#2a0e14',
        color: ok ? '#22D3A6' : '#FF3B5C',
        border: `1px solid ${ok ? '#22D3A680' : '#FF3B5C80'}`,
      }}
    >
      HTTP {status} · {outcome.toUpperCase()}
    </span>
  );
}

export function ScenarioShell({
  title,
  description,
  buttonLabel,
  running,
  onRun,
  error,
  children,
}: {
  title: string;
  description: string;
  buttonLabel: string;
  running: boolean;
  onRun: () => void;
  error: string | null;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-2xl border border-[#262626] bg-[#141414] p-6 flex flex-col gap-4">
      <div>
        <h3 className="text-base font-bold text-[#F5F5F5] mb-1">{title}</h3>
        <p className="text-sm text-[#A3A3A3] leading-relaxed">{description}</p>
      </div>
      <button
        onClick={onRun}
        disabled={running}
        className="self-start inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[#FF3B5C] text-black font-bold font-mono text-xs tracking-wide hover:bg-[#ff5470] active:scale-95 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {running ? 'RUNNING...' : buttonLabel}
      </button>
      {error && <p className="text-sm text-[#FF3B5C] font-mono">{error}</p>}
      {children}
    </section>
  );
}
