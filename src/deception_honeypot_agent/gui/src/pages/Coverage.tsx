import { useQuery } from "@tanstack/react-query";
import { getCoverage } from "../api/client";

export default function Coverage() {
  const { data, isLoading } = useQuery({ queryKey: ["coverage"], queryFn: getCoverage });

  if (isLoading) return <p>Loading…</p>;

  const pct = data?.coverage_percent ?? 0;
  const deployed: string[] = data?.deployed_types ?? [];
  const missing: string[] = data?.missing_types ?? [];
  const recs: string[] = data?.recommendations ?? [];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Decoy Coverage</h1>
      <div className="bg-gray-800 rounded p-6 mb-6 max-w-sm">
        <div className="text-5xl font-bold text-yellow-400 mb-2">{pct.toFixed(1)}%</div>
        <div className="text-gray-400 text-sm">Coverage against target types</div>
        <div className="mt-3 bg-gray-700 rounded-full h-3">
          <div
            className="bg-yellow-400 h-3 rounded-full transition-all"
            style={{ width: `${Math.min(pct, 100)}%` }}
          />
        </div>
      </div>
      <div className="grid grid-cols-2 gap-6">
        <div className="bg-gray-800 rounded p-4">
          <h2 className="font-semibold mb-3 text-green-400">Deployed Types</h2>
          {deployed.length === 0 ? (
            <p className="text-gray-500 text-sm">None</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {deployed.map((t) => <li key={t}>✓ {t}</li>)}
            </ul>
          )}
        </div>
        <div className="bg-gray-800 rounded p-4">
          <h2 className="font-semibold mb-3 text-red-400">Missing Types</h2>
          {missing.length === 0 ? (
            <p className="text-gray-500 text-sm">None — full coverage!</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {missing.map((t) => <li key={t}>✗ {t}</li>)}
            </ul>
          )}
        </div>
      </div>
      {recs.length > 0 && (
        <div className="mt-6 bg-gray-800 rounded p-4">
          <h2 className="font-semibold mb-3">Recommendations</h2>
          <ul className="space-y-1 text-sm text-gray-300">
            {recs.map((r, i) => <li key={i}>• {r}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}
