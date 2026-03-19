import { useQuery } from "@tanstack/react-query";
import { getAlerts } from "../api/client";

const SEV_COLOR: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-300",
  low: "text-green-400",
};

export default function Alerts() {
  const { data, isLoading } = useQuery({ queryKey: ["alerts"], queryFn: () => getAlerts() });
  const items: any[] = data?.items ?? [];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-2">Alerts</h1>
      <p className="text-gray-400 text-sm mb-6">Total: {data?.total ?? 0}</p>
      {isLoading ? (
        <p>Loading…</p>
      ) : items.length === 0 ? (
        <p className="text-gray-500">No alerts generated.</p>
      ) : (
        <div className="space-y-3">
          {items.map((a) => (
            <div key={a.alert_id} className="bg-gray-800 rounded p-4">
              <div className="flex justify-between mb-1">
                <span className="font-mono text-xs text-gray-400">{a.alert_id}</span>
                <span className={`font-bold text-sm uppercase ${SEV_COLOR[a.severity] ?? ""}`}>{a.severity}</span>
              </div>
              <div className="text-sm">{a.title ?? a.alert_id}</div>
              <div className="text-xs text-gray-500 mt-1">Source: {a.source_ip} | Decoy: {a.decoy_id}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
