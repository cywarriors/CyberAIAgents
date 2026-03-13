import { useQuery } from "@tanstack/react-query";
import {
  fetchAdminHealth,
  fetchAdminConfig,
  fetchAdminStatistics,
  fetchAuditLog,
  type AdminHealth,
  type AdminStatistics,
  type FeedbackEntry,
} from "../api/client";

export default function Administration() {
  const { data: health } = useQuery<AdminHealth>({
    queryKey: ["adminHealth"],
    queryFn: fetchAdminHealth,
    refetchInterval: 10_000,
  });

  const { data: config } = useQuery<Record<string, unknown>>({
    queryKey: ["adminConfig"],
    queryFn: fetchAdminConfig,
  });

  const { data: stats } = useQuery<AdminStatistics>({
    queryKey: ["adminStats"],
    queryFn: fetchAdminStatistics,
    refetchInterval: 15_000,
  });

  const { data: audit } = useQuery<FeedbackEntry[]>({
    queryKey: ["auditLog"],
    queryFn: fetchAuditLog,
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Administration</h1>

      {/* Health */}
      {health && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-3 text-sm font-semibold text-gray-300">Agent Health</h2>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6 text-sm">
            <div><p className="text-gray-400">Status</p><p className="font-medium text-green-400">{health.status}</p></div>
            <div><p className="text-gray-400">Uptime</p><p className="font-mono">{Math.round(health.uptime_seconds)}s</p></div>
            <div><p className="text-gray-400">Risk Scores</p><p className="font-mono">{health.risk_scores_in_store}</p></div>
            <div><p className="text-gray-400">Alerts</p><p className="font-mono">{health.alerts_in_store}</p></div>
            <div><p className="text-gray-400">Users</p><p className="font-mono">{health.users_tracked}</p></div>
            <div><p className="text-gray-400">SoD Violations</p><p className="font-mono">{health.sod_violations}</p></div>
          </div>
        </div>
      )}

      {/* Config */}
      {config && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-3 text-sm font-semibold text-gray-300">Configuration</h2>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 text-sm">
            {Object.entries(config).map(([k, v]) => (
              <div key={k}>
                <p className="text-gray-400">{k}</p>
                <p className="font-mono">{String(v)}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Statistics */}
      {stats && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-3 text-sm font-semibold text-gray-300">Statistics</h2>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 text-sm">
            <div><p className="text-gray-400">Risk Scores</p><p className="font-mono">{stats.total_risk_scores}</p></div>
            <div><p className="text-gray-400">Alerts</p><p className="font-mono">{stats.total_alerts}</p></div>
            <div><p className="text-gray-400">SoD Violations</p><p className="font-mono">{stats.sod_violations}</p></div>
            <div><p className="text-gray-400">Feedback</p><p className="font-mono">{stats.feedback_count}</p></div>
          </div>
          {Object.keys(stats.risk_level_distribution).length > 0 && (
            <div className="mt-3">
              <p className="text-xs text-gray-400 mb-1">Risk Level Distribution</p>
              <div className="flex gap-3 text-xs">
                {Object.entries(stats.risk_level_distribution).map(([k, v]) => (
                  <span key={k} className="rounded bg-gray-800 px-2 py-1">{k}: {v}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Audit Log */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
        <h2 className="mb-3 text-sm font-semibold text-gray-300">Audit Log</h2>
        {!audit || audit.length === 0 ? (
          <p className="text-gray-500 text-sm">No feedback recorded yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-left text-gray-400">
                  <th className="pb-2">Time</th>
                  <th className="pb-2">Alert</th>
                  <th className="pb-2">Analyst</th>
                  <th className="pb-2">Verdict</th>
                  <th className="pb-2">Notes</th>
                </tr>
              </thead>
              <tbody>
                {audit.map((f, i) => (
                  <tr key={i} className="border-b border-gray-800/50">
                    <td className="py-2 text-gray-400">{f.timestamp}</td>
                    <td className="py-2">{f.alert_id}</td>
                    <td className="py-2">{f.analyst_id}</td>
                    <td className="py-2">{f.verdict}</td>
                    <td className="py-2 max-w-xs truncate text-gray-400">{f.notes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
