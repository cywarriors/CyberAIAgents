import { useQuery } from "@tanstack/react-query";
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
import { AlertTriangle, Clock, CheckCircle, TrendingUp } from "lucide-react";
import { fetchDashboardSummary, type DashboardSummary } from "../api/client";

const PRIORITY_COLORS: Record<string, string> = {
  P1: "#ef4444",
  P2: "#f97316",
  P3: "#eab308",
  P4: "#22c55e",
};

export default function TriageDashboard() {
  const { data, isLoading } = useQuery<DashboardSummary>({
    queryKey: ["dashboard"],
    queryFn: fetchDashboardSummary,
    refetchInterval: 15_000,
  });

  if (isLoading || !data)
    return <p className="text-gray-400">Loading dashboard…</p>;

  const priorityData = Object.entries(data.priority_breakdown).map(
    ([name, value]) => ({ name, value }),
  );

  const kpis = [
    {
      label: "Open Incidents",
      value: data.open_incidents,
      icon: AlertTriangle,
      color: "text-red-400",
    },
    {
      label: "P1 Critical",
      value: data.p1_count,
      icon: AlertTriangle,
      color: "text-red-500",
    },
    {
      label: "MTTT",
      value: `${Math.round(data.mttt_seconds)}s`,
      icon: Clock,
      color: "text-yellow-400",
    },
    {
      label: "SLA Compliance",
      value: `${data.sla_compliance_pct}%`,
      icon: CheckCircle,
      color: "text-green-400",
    },
    {
      label: "Incidents Today",
      value: data.incidents_today,
      icon: TrendingUp,
      color: "text-blue-400",
    },
    {
      label: "Escalation Rate",
      value: `${data.escalation_rate}%`,
      icon: TrendingUp,
      color: "text-orange-400",
    },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Triage Dashboard</h1>

      {/* KPI cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        {kpis.map((k) => (
          <div
            key={k.label}
            className="rounded-xl border border-gray-800 bg-gray-900 p-4"
          >
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
        {/* Priority bar chart */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-4 text-sm font-semibold text-gray-300">
            Incidents by Priority
          </h2>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={priorityData}>
              <XAxis dataKey="name" stroke="#9ca3af" />
              <YAxis stroke="#9ca3af" allowDecimals={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#1f2937",
                  border: "1px solid #374151",
                }}
              />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {priorityData.map((d) => (
                  <Cell
                    key={d.name}
                    fill={PRIORITY_COLORS[d.name] ?? "#6366f1"}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Priority pie chart */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-4 text-sm font-semibold text-gray-300">
            Priority Distribution
          </h2>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={priorityData}
                cx="50%"
                cy="50%"
                outerRadius={90}
                dataKey="value"
                label={({ name, value }) => `${name}: ${value}`}
              >
                {priorityData.map((d) => (
                  <Cell
                    key={d.name}
                    fill={PRIORITY_COLORS[d.name] ?? "#6366f1"}
                  />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: "#1f2937",
                  border: "1px solid #374151",
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top categories */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
        <h2 className="mb-4 text-sm font-semibold text-gray-300">
          Top Categories
        </h2>
        {data.top_categories.length === 0 ? (
          <p className="text-gray-500 text-sm">No category data yet.</p>
        ) : (
          <div className="space-y-2">
            {data.top_categories.map((cat, i) => (
              <div key={i} className="flex items-center justify-between">
                <span className="text-sm text-gray-300">{cat.category}</span>
                <span className="rounded bg-gray-800 px-2 py-0.5 text-xs font-medium">
                  {cat.count}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
