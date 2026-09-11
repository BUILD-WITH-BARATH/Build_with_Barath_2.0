import { OwnershipScenario } from './scenarios/OwnershipScenario';
import { BatchScenario } from './scenarios/BatchScenario';
import { AbacScenario } from './scenarios/AbacScenario';
import { CanaryScenario } from './scenarios/CanaryScenario';

export function DemoPage({ apiBase }: { apiBase: string }) {
  return (
    <div className="max-w-5xl mx-auto px-6 py-14 flex flex-col gap-6">
      <div>
        <h2 className="text-2xl font-bold text-[#F5F5F5] mb-2">Live defense, four ways</h2>
        <p className="text-sm text-[#A3A3A3] max-w-2xl leading-relaxed">
          Every scenario below fires real HTTP requests at the real backend — no mocked
          data, no canned responses. Run them in order or any order you like.
        </p>
      </div>
      <OwnershipScenario apiBase={apiBase} />
      <BatchScenario apiBase={apiBase} />
      <AbacScenario apiBase={apiBase} />
      <CanaryScenario apiBase={apiBase} />
    </div>
  );
}
