import { useQuery } from "@tanstack/react-query";
import { fetchDashboard, type DashboardSummary } from "../api/client";
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

const COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#2563eb",
  info: "#6b7280",
};

function SeverityPie({ data }: { data: DashboardSummary }) {
  const chart = Object.entries(data.severity_breakdown)
    .map(([name, value]) => ({ name, value }))
    .filter((d) => d.value > 0);

  if (chart.length === 0) return <p className="text-gray-500">No findings yet</p>;

  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie data={chart} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} label>
          {chart.map((entry) => (
            <Cell key={entry.name} fill={COLORS[entry.name] ?? "#6b7280"} />
          ))}
        </Pie>
        <Tooltip />
      </PieChart>
    </ResponsiveContainer>
  );
}

function StatCard({ label, value, accent }: { label: string; value: number | string; accent?: string }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
      <p className="text-xs uppercase tracking-wider text-gray-500">{label}</p>
      <p className={`mt-1 text-3xl font-bold ${accent ?? "text-white"}`}>{value}</p>
    </div>
  );
}

export default function Dashboard() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["dashboard"],
    queryFn: fetchDashboard,
    refetchInterval: 15_000,
  });

  if (isLoading) return <p className="text-gray-400">Loading dashboard…</p>;
  if (error) return <p className="text-red-400">Error loading dashboard</p>;
  if (!data) return null;

  const barData = [
    { name: "critical", count: data.critical_findings },
    { name: "high", count: data.high_findings },
    { name: "medium", count: data.medium_findings },
    { name: "low", count: data.low_findings },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
        <StatCard label="Active Engagements" value={data.active_engagements} accent="text-brand-500" />
        <StatCard label="Total Findings" value={data.total_findings} />
        <StatCard label="Critical" value={data.critical_findings} accent="text-severity-critical" />
        <StatCard label="Attack Paths" value={data.attack_paths_found} accent="text-orange-400" />
        <StatCard label="Reports" value={data.reports_generated} />
      </div>

      {/* Charts */}
      <div className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="mb-4 font-semibold">Findings by Severity</h2>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={barData}>
              <XAxis dataKey="name" tick={{ fill: "#9ca3af", fontSize: 12 }} />
              <YAxis allowDecimals={false} tick={{ fill: "#9ca3af", fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                {barData.map((entry) => (
                  <Cell key={entry.name} fill={COLORS[entry.name] ?? "#6b7280"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="mb-4 font-semibold">Severity Distribution</h2>
          <SeverityPie data={data} />
        </div>
      </div>
    </div>
  );
}
