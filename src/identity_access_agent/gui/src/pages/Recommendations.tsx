import { useQuery } from "@tanstack/react-query";
import { fetchRecommendations, type RecommendationItem } from "../api/client";

const CONTROL_COLORS: Record<string, string> = {
  session_kill: "text-red-400 bg-red-900/30",
  step_up_mfa: "text-orange-400 bg-orange-900/30",
  temporary_lockout: "text-yellow-400 bg-yellow-900/30",
  password_reset: "text-yellow-400 bg-yellow-900/30",
  access_review: "text-blue-400 bg-blue-900/30",
  monitor: "text-green-400 bg-green-900/30",
  no_action: "text-gray-400 bg-gray-800/30",
};

export default function Recommendations() {
  const { data, isLoading } = useQuery<RecommendationItem[]>({
    queryKey: ["recommendations"],
    queryFn: () => fetchRecommendations(),
    refetchInterval: 15_000,
  });

  if (isLoading) return <p className="text-gray-400">Loading recommendations…</p>;

  const items = data ?? [];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Control Recommendations</h1>
      {items.length === 0 ? (
        <p className="text-gray-500">No recommendations yet.</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-900">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-gray-400">
                <th className="p-3">User</th>
                <th className="p-3">Control</th>
                <th className="p-3">Risk</th>
                <th className="p-3">Auto</th>
                <th className="p-3">Reason</th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.user_id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="p-3 font-medium">{r.username || r.user_id}</td>
                  <td className="p-3">
                    <span className={`rounded px-2 py-0.5 text-xs font-semibold ${CONTROL_COLORS[r.control] ?? ""}`}>
                      {r.control}
                    </span>
                  </td>
                  <td className="p-3 font-mono">{r.risk_score.toFixed(1)} ({r.risk_level})</td>
                  <td className="p-3">{r.auto_enforce ? "Yes" : "No"}</td>
                  <td className="p-3 max-w-xs truncate text-gray-400">{r.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
