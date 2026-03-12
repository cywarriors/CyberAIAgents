import { useQuery } from "@tanstack/react-query";
import { fetchAnomalies, type Anomaly } from "../api/client";
import { Activity } from "lucide-react";

function scoreColor(score: number): string {
  if (score >= 0.8) return "text-red-400";
  if (score >= 0.6) return "text-orange-400";
  if (score >= 0.4) return "text-yellow-400";
  return "text-green-400";
}

export default function AnomalyExplorer() {
  const { data: anomalies = [], isLoading } = useQuery({
    queryKey: ["anomalies"],
    queryFn: () => fetchAnomalies(),
    refetchInterval: 15_000,
  });

  if (isLoading) return <p className="text-gray-400">Loading anomalies…</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Anomaly Explorer</h1>

      {/* Anomaly cards */}
      <div className="space-y-3">
        {anomalies.map((a: Anomaly) => (
          <div
            key={a.anomaly_id}
            className="rounded-xl border border-gray-800 bg-gray-900 p-4"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Activity className="h-5 w-5 text-brand-500" />
                <div>
                  <p className="font-medium text-white">{a.anomaly_type}</p>
                  <p className="text-xs text-gray-500">
                    {a.entity_type}: {a.entity_id} &bull;{" "}
                    {new Date(a.timestamp).toLocaleString()}
                  </p>
                </div>
              </div>
              <span className={`text-lg font-bold ${scoreColor(a.anomaly_score)}`}>
                {(a.anomaly_score * 100).toFixed(0)}%
              </span>
            </div>

            {/* Baseline vs Observed */}
            <div className="mt-3 grid grid-cols-2 gap-4 text-sm">
              <div className="rounded-lg bg-gray-800 px-3 py-2">
                <span className="text-xs text-gray-500">Baseline</span>
                <p className="text-white">{a.baseline_value.toFixed(2)}</p>
              </div>
              <div className="rounded-lg bg-gray-800 px-3 py-2">
                <span className="text-xs text-gray-500">Observed</span>
                <p className="text-white">{a.observed_value.toFixed(2)}</p>
              </div>
            </div>

            {a.description && (
              <p className="mt-2 text-xs text-gray-400">{a.description}</p>
            )}
          </div>
        ))}
        {anomalies.length === 0 && (
          <p className="py-8 text-center text-gray-500">No anomalies detected.</p>
        )}
      </div>
    </div>
  );
}
