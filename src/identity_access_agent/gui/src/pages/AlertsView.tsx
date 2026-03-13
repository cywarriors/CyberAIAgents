import { useQuery } from "@tanstack/react-query";
import { fetchAlerts, type AlertItem } from "../api/client";

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-900/30",
  high: "text-orange-400 bg-orange-900/30",
  medium: "text-yellow-400 bg-yellow-900/30",
  low: "text-green-400 bg-green-900/30",
};

export default function AlertsView() {
  const { data, isLoading } = useQuery<AlertItem[]>({
    queryKey: ["alerts"],
    queryFn: () => fetchAlerts(),
    refetchInterval: 15_000,
  });

  if (isLoading) return <p className="text-gray-400">Loading alerts…</p>;

  const items = data ?? [];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Identity Alerts</h1>
      {items.length === 0 ? (
        <p className="text-gray-500">No alerts yet.</p>
      ) : (
        <div className="space-y-3">
          {items.map((a) => (
            <div key={a.alert_id} className="rounded-xl border border-gray-800 bg-gray-900 p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className={`rounded px-2 py-0.5 text-xs font-semibold ${SEV_COLORS[a.severity] ?? ""}`}>
                    {a.severity}
                  </span>
                  <span className="font-medium">{a.title}</span>
                </div>
                <span className={`text-xs ${a.status === "open" ? "text-yellow-400" : "text-gray-500"}`}>
                  {a.status}
                </span>
              </div>
              <p className="mt-2 text-sm text-gray-400">{a.description}</p>
              <div className="mt-2 flex gap-4 text-xs text-gray-500">
                <span>User: {a.username || a.user_id}</span>
                <span>Score: {a.risk_score.toFixed(1)}</span>
                <span>Control: {a.recommended_control}</span>
                {a.ticket_id && <span>Ticket: {a.ticket_id}</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
