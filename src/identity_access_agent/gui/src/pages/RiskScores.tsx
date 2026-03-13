import { useQuery } from "@tanstack/react-query";
import { fetchRiskScores, type RiskScoreItem } from "../api/client";

const LEVEL_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-900/30",
  high: "text-orange-400 bg-orange-900/30",
  medium: "text-yellow-400 bg-yellow-900/30",
  low: "text-green-400 bg-green-900/30",
};

export default function RiskScores() {
  const { data, isLoading } = useQuery<RiskScoreItem[]>({
    queryKey: ["riskScores"],
    queryFn: () => fetchRiskScores(),
    refetchInterval: 15_000,
  });

  if (isLoading) return <p className="text-gray-400">Loading risk scores…</p>;

  const items = data ?? [];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Identity Risk Scores</h1>
      {items.length === 0 ? (
        <p className="text-gray-500">No risk scores computed yet.</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-900">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-gray-400">
                <th className="p-3">User</th>
                <th className="p-3">Score</th>
                <th className="p-3">Level</th>
                <th className="p-3">Control</th>
                <th className="p-3">Confidence</th>
                <th className="p-3">Explanation</th>
              </tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.user_id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="p-3 font-medium">{s.username || s.user_id}</td>
                  <td className="p-3 font-mono">{s.risk_score.toFixed(1)}</td>
                  <td className="p-3">
                    <span className={`rounded px-2 py-0.5 text-xs font-semibold ${LEVEL_COLORS[s.risk_level] ?? ""}`}>
                      {s.risk_level}
                    </span>
                  </td>
                  <td className="p-3">{s.recommended_control}</td>
                  <td className="p-3 font-mono">{(s.confidence * 100).toFixed(0)}%</td>
                  <td className="p-3 max-w-xs truncate text-gray-400">{s.explanation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
