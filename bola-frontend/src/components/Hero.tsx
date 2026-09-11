interface HeroProps {
  onSeeDemo: () => void;
}

const DIFFERENTIATORS = [
  {
    title: '9 attack vectors, one engine',
    body: 'Ownership checks, batch/bulk arrays, GraphQL traversal, async job second-order access, hierarchical chains, dynamic ABAC + field redaction, and honeypot canaries — not just a single allow/deny rule.',
  },
  {
    title: 'Real-time, not offline scanning',
    body: 'Every request is scored live against a behavioral risk engine and an anomaly model — not a nightly batch job or a static code scanner.',
  },
  {
    title: 'Drop-in for any backend',
    body: 'One HTTP call — POST /v1/authorize — from any API in any language. No rewrite, no framework lock-in.',
  },
  {
    title: 'Self-audited, not just self-claimed',
    body: 'We run our own full-codebase security audits and publish real fixes with commit-level evidence, including a cross-tenant vulnerability we found and patched in our own async job path.',
  },
];

export function Hero({ onSeeDemo }: HeroProps) {
  return (
    <div className="flex flex-col">
      <section className="relative overflow-hidden border-b border-[#262626] bg-gradient-to-b from-[#141414] to-[#0A0A0A]">
        <div className="max-w-5xl mx-auto px-6 py-20 flex flex-col items-start gap-6">
          <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#1c0e11] border border-[#FF3B5C]/40 text-[#FF3B5C] text-xs font-mono tracking-wide">
            OWASP API1:2023 · BROKEN OBJECT LEVEL AUTHORIZATION
          </span>
          <h1 className="text-4xl md:text-5xl font-bold text-[#F5F5F5] leading-tight max-w-3xl">
            The #1 API vulnerability has no real-time defense.
            <span className="text-[#FF3B5C]"> We built one.</span>
          </h1>
          <p className="text-base text-[#A3A3A3] max-w-2xl leading-relaxed">
            INTEGRITY checks object-level ownership on every request, scores it with a
            behavioral risk engine and an anomaly model, and blocks it — live, not after
            the fact. See it catch a real attack below, against a real backend, in real time.
          </p>
          <div className="flex gap-3 mt-2">
            <button
              onClick={onSeeDemo}
              className="px-6 py-3 rounded-xl bg-[#FF3B5C] text-black font-bold font-mono text-sm tracking-wide hover:bg-[#ff5470] active:scale-95 transition-all"
            >
              ▶ SEE IT BLOCK A LIVE ATTACK
            </button>
          </div>
        </div>
      </section>

      <section className="max-w-5xl mx-auto px-6 py-16 w-full">
        <h2 className="text-xs font-bold tracking-wider text-[#737373] uppercase mb-6">Why this is different</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {DIFFERENTIATORS.map((d) => (
            <div key={d.title} className="rounded-2xl border border-[#262626] bg-[#141414] p-5">
              <h3 className="text-sm font-bold text-[#F5F5F5] mb-2">{d.title}</h3>
              <p className="text-sm text-[#A3A3A3] leading-relaxed">{d.body}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
