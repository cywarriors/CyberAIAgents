import { useQuery } from "@tanstack/react-query";
import { getDashboard } from "../api/client";

export default function Dashboard() {
  const { data, isLoading } = useQuery({ queryKey: ["dashboard"], queryFn: getDashboard });

  if (isLoading) return <p>Loading…</p>;

  const summary = data?.summary ?? {};
  const stats = [
    { label: "Decoys Deployed", value: summary.decoy_count ?? 0 },
    { label: "Interactions", value: summary.interaction_count ?? 0 },
    { label: "Alerts", value: summary.alert_count ?? 0 },
    { label: "Attacker Profiles", value: summary.profile_count ?? 0 },
    { label: "Coverage %", value: `${(summary.coverage_percent ?? 0).toFixed(1)}%` },
  ];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Dashboard</h1>
      <div className="grid grid-cols-5 gap-4 mb-8">
        {stats.map(({ label, value }) => (
          <div key={label} className="bg-gray-800 rounded p-4">
            <div className="text-2xl font-bold text-yellow-400">{value}</div>
            <div className="text-sm text-gray-400 mt-1">{label}</div>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-2 gap-6">
        <div className="bg-gray-800 rounded p-4">
          <h2 className="font-semibold mb-3">Recent Alerts</h2>
          {(data?.recent_alerts ?? []).length === 0 ? (
            <p className="text-gray-500 text-sm">No alerts</p>
          ) : (
            <ul className="space-y-2">
              {(data.recent_alerts as any[]).map((a: any) => (
                <li key={a.alert_id} className="text-sm flex justify-between">
                  <span>{a.alert_id}</span>
                  <span className={a.severity === "critical" ? "text-red-400" : "text-yellow-300"}>{a.severity}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="bg-gray-800 rounded p-4">
          <h2 className="font-semibold mb-3">Recent Interactions</h2>
          {(data?.recent_interactions ?? []).length === 0 ? (
            <p className="text-gray-500 text-sm">No interactions</p>
          ) : (
            <ul className="space-y-2">
              {(data.recent_interactions as any[]).map((i: any) => (
                <li key={i.interaction_id} className="text-sm flex justify-between">
                  <span>{i.source_ip ?? "unknown"}</span>
                  <span className="text-gray-400">{i.interaction_type ?? i.action}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
