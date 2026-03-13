import { useQuery } from "@tanstack/react-query";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { GraduationCap, Users, Target, TrendingUp } from "lucide-react";
import { fetchAwarenessMetrics, type AwarenessMetrics } from "../api/client";

const DEPT_COLORS = [
  "#3b82f6",
  "#ef4444",
  "#f97316",
  "#eab308",
  "#22c55e",
  "#8b5cf6",
  "#ec4899",
  "#06b6d4",
];

export default function UserAwareness() {
  const { data, isLoading } = useQuery<AwarenessMetrics>({
    queryKey: ["awareness"],
    queryFn: fetchAwarenessMetrics,
    refetchInterval: 30_000,
  });

  if (isLoading || !data)
    return <p className="text-gray-400">Loading awareness data…</p>;

  const deptData = Object.entries(data.reports_by_department).map(([name, value]) => ({
    name,
    value,
  }));

  const kpis = [
    {
      label: "Total Reports",
      value: data.total_reports,
      icon: Users,
      color: "text-blue-400",
    },
    {
      label: "Report Accuracy",
      value: `${data.report_accuracy_pct}%`,
      icon: Target,
      color: "text-green-400",
    },
    {
      label: "Training Completion",
      value: `${data.training_completion_pct}%`,
      icon: GraduationCap,
      color: "text-purple-400",
    },
    {
      label: "Simulation Click Rate",
      value: `${data.simulation_click_rate}%`,
      icon: TrendingUp,
      color: "text-red-400",
    },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">User Awareness Dashboard</h1>

      {/* KPI cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {kpis.map((k) => (
          <div key={k.label} className="rounded-xl border border-gray-800 bg-gray-900 p-4">
            <div className="flex items-center gap-2">
              <k.icon className={`h-4 w-4 ${k.color}`} />
              <span className="text-xs text-gray-400">{k.label}</span>
            </div>
            <p className="mt-2 text-2xl font-bold">{k.value}</p>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Reporting trend */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-4 text-sm font-semibold text-gray-300">Reporting Trend</h2>
          {data.reporting_trend.length === 0 ? (
            <p className="text-gray-500 text-sm">No trend data yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={data.reporting_trend}>
                <XAxis dataKey="date" stroke="#9ca3af" />
                <YAxis stroke="#9ca3af" allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#1f2937", border: "1px solid #374151" }}
                />
                <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Department breakdown */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-4 text-sm font-semibold text-gray-300">Reports by Department</h2>
          {deptData.length === 0 ? (
            <p className="text-gray-500 text-sm">No department data yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={deptData}
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {deptData.map((_, i) => (
                    <Cell key={i} fill={DEPT_COLORS[i % DEPT_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: "#1f2937", border: "1px solid #374151" }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Accuracy rates */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
        <h2 className="mb-3 text-sm font-semibold text-gray-300">Rates</h2>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div>
            <p className="text-xs text-gray-400">Report Accuracy</p>
            <div className="mt-1 h-2 rounded bg-gray-700">
              <div
                className="h-2 rounded bg-green-500"
                style={{ width: `${data.report_accuracy_pct}%` }}
              />
            </div>
            <p className="mt-1 text-sm font-medium">{data.report_accuracy_pct}%</p>
          </div>
          <div>
            <p className="text-xs text-gray-400">Training Completion</p>
            <div className="mt-1 h-2 rounded bg-gray-700">
              <div
                className="h-2 rounded bg-purple-500"
                style={{ width: `${data.training_completion_pct}%` }}
              />
            </div>
            <p className="mt-1 text-sm font-medium">{data.training_completion_pct}%</p>
          </div>
          <div>
            <p className="text-xs text-gray-400">Simulation Click Rate</p>
            <div className="mt-1 h-2 rounded bg-gray-700">
              <div
                className="h-2 rounded bg-red-500"
                style={{ width: `${data.simulation_click_rate}%` }}
              />
            </div>
            <p className="mt-1 text-sm font-medium">{data.simulation_click_rate}%</p>
          </div>
          <div>
            <p className="text-xs text-gray-400">True-Positive Reports</p>
            <div className="mt-1 h-2 rounded bg-gray-700">
              <div
                className="h-2 rounded bg-blue-500"
                style={{
                  width: `${data.total_reports ? Math.round((data.true_positive_reports / data.total_reports) * 100) : 0}%`,
                }}
              />
            </div>
            <p className="mt-1 text-sm font-medium">
              {data.true_positive_reports}/{data.total_reports}
            </p>
          </div>
        </div>
      </div>

      {/* Top reporters */}
      {data.top_reporters.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-3 text-sm font-semibold text-gray-300">Top Reporters</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-gray-800">
                <tr>
                  <th className="px-4 py-2 text-left font-medium text-gray-400">Email</th>
                  <th className="px-4 py-2 text-left font-medium text-gray-400">Reports</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {data.top_reporters.map((r) => (
                  <tr key={r.email}>
                    <td className="px-4 py-2">{r.email}</td>
                    <td className="px-4 py-2 font-mono">{r.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
