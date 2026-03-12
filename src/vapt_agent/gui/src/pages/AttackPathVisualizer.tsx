import { useQuery } from "@tanstack/react-query";
import { fetchAttackPaths, type AttackPath } from "../api/client";

const RISK_COLOR = (r: number) => {
  if (r >= 8) return "text-red-400 border-red-800 bg-red-950";
  if (r >= 5) return "text-orange-400 border-orange-800 bg-orange-950";
  return "text-yellow-400 border-yellow-800 bg-yellow-950";
};

export default function AttackPathVisualizer() {
  const { data: paths = [], isLoading } = useQuery({
    queryKey: ["attack-paths"],
    queryFn: () => fetchAttackPaths(),
  });

  if (isLoading) return <p className="text-gray-400">Loading attack paths…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Attack Path Visualizer</h1>

      {paths.length === 0 && (
        <p className="py-8 text-center text-gray-500">
          No attack paths discovered yet. Run scans to generate paths.
        </p>
      )}

      {paths.map((path: AttackPath) => (
        <div
          key={path.id}
          className="rounded-xl border border-gray-800 bg-gray-900 p-5 space-y-4"
        >
          <div className="flex items-center justify-between">
            <h2 className="font-semibold text-white">
              Path &middot; {path.steps.length} steps
            </h2>
            <span
              className={`rounded-full border px-3 py-1 text-sm font-bold ${RISK_COLOR(
                path.composite_risk,
              )}`}
            >
              Risk: {path.composite_risk.toFixed(1)}
            </span>
          </div>

          {/* Visual chain */}
          <div className="flex flex-wrap items-center gap-2">
            {path.steps.map((step, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <div className="rounded-lg border border-gray-700 bg-gray-800 p-3 text-sm">
                  <p className="font-mono font-medium text-white">{step.asset_id}</p>
                  <p className="text-xs text-gray-400">{step.technique}</p>
                  {step.mitre_technique_id && (
                    <p className="text-xs text-gray-500">{step.mitre_technique_id}</p>
                  )}
                  <p className="mt-1 text-xs font-bold text-orange-400">
                    Step {step.step}
                  </p>
                </div>
                {idx < path.steps.length - 1 && (
                  <span className="text-gray-600">→</span>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
