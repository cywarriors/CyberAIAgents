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
import { Target, TrendingUp, AlertTriangle, CheckCircle } from "lucide-react";
import { fetchTriageMetrics, type TriageMetrics } from "../api/client";

const CATEGORY_COLORS = [
  "#3b82f6",
  "#ef4444",
  "#f97316",
  "#eab308",
  "#22c55e",
  "#8b5cf6",
  "#ec4899",
  "#06b6d4",
];

export default function TriageAnalytics() {
  const { data, isLoading } = useQuery<TriageMetrics>({
    queryKey: ["triage-metrics"],
    queryFn: fetchTriageMetrics,
    refetchInterval: 30_000,
  });

  if (isLoading || !data)
    return <p className="text-gray-400">Loading analytics…</p>;

  const categoryData = Object.entries(data.category_distribution).map(
    ([name, value]) => ({ name, value }),
  );

  const kpis = [
    {
      label: "Total Triaged",
      value: data.total_triaged,
      icon: Target,
      color: "text-blue-400",
    },
    {
      label: "Priority Accuracy",
      value: `${data.priority_accuracy}%`,
      icon: CheckCircle,
      color: "text-green-400",
    },
    {
      label: "TP Rate",
      value: `${data.true_positive_rate}%`,
      icon: TrendingUp,
      color: "text-green-400",
    },
    {
      label: "FP Rate",
      value: `${data.false_positive_rate}%`,
      icon: AlertTriangle,
      color: "text-red-400",
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
      <h1 className="text-2xl font-bold">Triage Analytics</h1>

      {/* KPI cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
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

      {/* Charts */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Category bar chart */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-4 text-sm font-semibold text-gray-300">
            Category Distribution
          </h2>
          {categoryData.length === 0 ? (
            <p className="text-gray-500 text-sm">No data yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={categoryData}>
                <XAxis dataKey="name" stroke="#9ca3af" />
                <YAxis stroke="#9ca3af" allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#1f2937",
                    border: "1px solid #374151",
                  }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {categoryData.map((_, i) => (
                    <Cell
                      key={i}
                      fill={CATEGORY_COLORS[i % CATEGORY_COLORS.length]}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Category pie chart */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-4 text-sm font-semibold text-gray-300">
            Category Breakdown
          </h2>
          {categoryData.length === 0 ? (
            <p className="text-gray-500 text-sm">No data yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={categoryData}
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {categoryData.map((_, i) => (
                    <Cell
                      key={i}
                      fill={CATEGORY_COLORS[i % CATEGORY_COLORS.length]}
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
          )}
        </div>
      </div>

      {/* Verdicts summary */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
        <h2 className="mb-3 text-sm font-semibold text-gray-300">Verdict Rates</h2>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div>
            <p className="text-xs text-gray-400">True Positive</p>
            <div className="mt-1 h-2 rounded bg-gray-700">
              <div
                className="h-2 rounded bg-green-500"
                style={{ width: `${data.true_positive_rate}%` }}
              />
            </div>
            <p className="mt-1 text-sm font-medium">{data.true_positive_rate}%</p>
          </div>
          <div>
            <p className="text-xs text-gray-400">False Positive</p>
            <div className="mt-1 h-2 rounded bg-gray-700">
              <div
                className="h-2 rounded bg-red-500"
                style={{ width: `${data.false_positive_rate}%` }}
              />
            </div>
            <p className="mt-1 text-sm font-medium">{data.false_positive_rate}%</p>
          </div>
          <div>
            <p className="text-xs text-gray-400">Escalation</p>
            <div className="mt-1 h-2 rounded bg-gray-700">
              <div
                className="h-2 rounded bg-orange-500"
                style={{ width: `${data.escalation_rate}%` }}
              />
            </div>
            <p className="mt-1 text-sm font-medium">{data.escalation_rate}%</p>
          </div>
          <div>
            <p className="text-xs text-gray-400">Priority Accuracy</p>
            <div className="mt-1 h-2 rounded bg-gray-700">
              <div
                className="h-2 rounded bg-blue-500"
                style={{ width: `${data.priority_accuracy}%` }}
              />
            </div>
            <p className="mt-1 text-sm font-medium">{data.priority_accuracy}%</p>
          </div>
        </div>
      </div>
    </div>
  );
}
