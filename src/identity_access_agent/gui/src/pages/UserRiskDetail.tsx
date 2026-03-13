import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getUser, getUserRiskScore, type UserRiskItem, type RiskScoreItem } from "../api/client";

export default function UserRiskDetail() {
  const { id } = useParams<{ id: string }>();

  const { data: user, isLoading: loadingUser } = useQuery<UserRiskItem>({
    queryKey: ["user", id],
    queryFn: () => getUser(id!),
    enabled: !!id,
  });

  const { data: score, isLoading: loadingScore } = useQuery<RiskScoreItem>({
    queryKey: ["riskScore", id],
    queryFn: () => getUserRiskScore(id!),
    enabled: !!id,
  });

  if (loadingUser || loadingScore)
    return <p className="text-gray-400">Loading user details…</p>;

  if (!user) return <p className="text-gray-500">User not found.</p>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{user.username || user.user_id}</h1>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <p className="text-xs text-gray-400">Risk Score</p>
          <p className="mt-1 text-2xl font-bold">{user.risk_score.toFixed(1)}</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <p className="text-xs text-gray-400">Risk Level</p>
          <p className="mt-1 text-2xl font-bold capitalize">{user.risk_level}</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <p className="text-xs text-gray-400">Active Alerts</p>
          <p className="mt-1 text-2xl font-bold">{user.active_alerts}</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <p className="text-xs text-gray-400">SoD Violations</p>
          <p className="mt-1 text-2xl font-bold">{user.sod_violations}</p>
        </div>
      </div>

      {score && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-4 text-sm font-semibold text-gray-300">Risk Explanation</h2>
          <p className="text-sm text-gray-400">{score.explanation}</p>

          {score.indicators.length > 0 && (
            <>
              <h3 className="mt-4 mb-2 text-sm font-semibold text-gray-300">Risk Indicators</h3>
              <ul className="space-y-1">
                {score.indicators.map((ind, i) => (
                  <li key={i} className="text-sm text-gray-400">
                    <span className="font-medium text-gray-300">{ind.indicator_type}:</span>{" "}
                    {ind.description}
                  </li>
                ))}
              </ul>
            </>
          )}

          {Object.keys(score.components).length > 0 && (
            <>
              <h3 className="mt-4 mb-2 text-sm font-semibold text-gray-300">Score Components</h3>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                {Object.entries(score.components).map(([k, v]) => (
                  <div key={k} className="rounded border border-gray-800 p-2 text-sm">
                    <p className="text-gray-400">{k}</p>
                    <p className="font-mono">{v.toFixed(1)}</p>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
