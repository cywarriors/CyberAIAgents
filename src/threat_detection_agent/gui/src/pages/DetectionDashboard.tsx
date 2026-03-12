import { useQuery } from "@tanstack/react-query";
import { fetchDashboardMetrics } from "../api/client";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { AlertTriangle, Activity, BookOpen, Gauge } from "lucide-react";

const SEV_COLORS: Record<string, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#22c55e",
  Info: "#3b82f6",
};

export default function DetectionDashboard() {
  const { data, isLoading } = useQuery({
    queryKey: ["dashboard"],
    queryFn: fetchDashboardMetrics,
    refetchInterval: 15_000,
  });

  if (isLoading || !data) return <p className="text-gray-400">Loading dashboard…</p>;

  const barData = [
    { name: "Critical", count: data.critical_alerts, fill: SEV_COLORS.Critical },
    { name: "High", count: data.high_alerts, fill: SEV_COLORS.High },
    { name: "Medium", count: data.medium_alerts, fill: SEV_COLORS.Medium },
    { name: "Low", count: data.low_alerts, fill: SEV_COLORS.Low },
    { name: "Info", count: data.info_alerts, fill: SEV_COLORS.Info },
  ];

  const pieData = Object.entries(data.severity_breakdown).map(([name, value]) => ({
    name,
    value,
  }));

  const kpis = [
    { label: "Total Alerts", value: data.total_alerts, icon: AlertTriangle },
    { label: "Active Anomalies", value: data.active_anomalies, icon: Activity },
    { label: "Rules Deployed", value: data.rules_deployed, icon: BookOpen },
    { label: "MTTD", value: `${data.mttd_seconds.toFixed(0)}s`, icon: Gauge },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Detection Dashboard</h1>

      {/* KPI cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {kpis.map(({ label, value, icon: Icon }) => (
          <div
            key={label}
            className="rounded-xl border border-gray-800 bg-gray-900 p-5"
          >
            <div className="flex items-center gap-2 text-gray-400">
              <Icon className="h-4 w-4" />
              <span className="text-xs uppercase">{label}</span>
            </div>
            <p className="mt-2 text-2xl font-bold text-white">{value}</p>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Severity bar chart */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="mb-4 text-sm font-semibold text-gray-300">Severity Distribution</h2>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={barData}>
              <XAxis dataKey="name" tick={{ fill: "#9ca3af", fontSize: 12 }} />
              <YAxis tick={{ fill: "#9ca3af", fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="count">
                {barData.map((d, i) => (
                  <Cell key={i} fill={d.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Severity pie */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="mb-4 text-sm font-semibold text-gray-300">Alert Breakdown</h2>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} label>
                {pieData.map((d, i) => (
                  <Cell key={i} fill={SEV_COLORS[d.name] ?? "#6b7280"} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top triggered rules */}
      {data.top_triggered_rules.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="mb-4 text-sm font-semibold text-gray-300">Top Triggered Rules</h2>
          <div className="space-y-2">
            {data.top_triggered_rules.map((r) => (
              <div key={r.rule_id} className="flex items-center justify-between rounded-lg bg-gray-800 px-4 py-2">
                <span className="text-sm text-white">{r.rule_name}</span>
                <span className="text-xs text-gray-400">{r.hit_count} hits</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
