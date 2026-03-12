import { useQuery } from "@tanstack/react-query";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { Users, Clock, CheckCircle } from "lucide-react";
import {
  fetchAnalystWorkload,
  type AnalystWorkloadItem,
} from "../api/client";

export default function AnalystWorkload() {
  const { data, isLoading } = useQuery<AnalystWorkloadItem[]>({
    queryKey: ["analyst-workload"],
    queryFn: fetchAnalystWorkload,
    refetchInterval: 15_000,
  });

  if (isLoading) return <p className="text-gray-400">Loading…</p>;

  const analysts = data ?? [];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Analyst Workload</h1>

      {analysts.length === 0 ? (
        <p className="text-gray-500 text-sm">No analyst data available.</p>
      ) : (
        <>
          {/* KPI summary */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
              <div className="flex items-center gap-2">
                <Users className="h-4 w-4 text-blue-400" />
                <span className="text-xs text-gray-400">Active Analysts</span>
              </div>
              <p className="mt-2 text-2xl font-bold">{analysts.length}</p>
            </div>
            <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-yellow-400" />
                <span className="text-xs text-gray-400">Avg Handling Time</span>
              </div>
              <p className="mt-2 text-2xl font-bold">
                {analysts.length
                  ? `${Math.round(
                      analysts.reduce((s, a) => s + a.avg_handling_time_seconds, 0) /
                        analysts.length,
                    )}s`
                  : "—"}
              </p>
            </div>
            <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-400" />
                <span className="text-xs text-gray-400">Resolved Today</span>
              </div>
              <p className="mt-2 text-2xl font-bold">
                {analysts.reduce((s, a) => s + a.resolved_today, 0)}
              </p>
            </div>
          </div>

          {/* Bar chart */}
          <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
            <h2 className="mb-4 text-sm font-semibold text-gray-300">
              Open Incidents per Analyst
            </h2>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={analysts}>
                <XAxis dataKey="analyst_name" stroke="#9ca3af" />
                <YAxis stroke="#9ca3af" allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#1f2937",
                    border: "1px solid #374151",
                  }}
                />
                <Bar dataKey="open_incidents" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Table */}
          <div className="overflow-x-auto rounded-xl border border-gray-800">
            <table className="w-full text-sm">
              <thead className="border-b border-gray-800 bg-gray-900">
                <tr>
                  <th className="px-4 py-3 text-left font-medium text-gray-400">Analyst</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-400">
                    Open Incidents
                  </th>
                  <th className="px-4 py-3 text-left font-medium text-gray-400">
                    Avg Handling (s)
                  </th>
                  <th className="px-4 py-3 text-left font-medium text-gray-400">
                    Resolved Today
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {analysts.map((a) => (
                  <tr key={a.analyst_id} className="hover:bg-gray-800/50">
                    <td className="px-4 py-3 font-medium">{a.analyst_name}</td>
                    <td className="px-4 py-3">{a.open_incidents}</td>
                    <td className="px-4 py-3">{Math.round(a.avg_handling_time_seconds)}</td>
                    <td className="px-4 py-3">{a.resolved_today}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
