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
import { ShieldAlert, ShieldCheck, AlertTriangle, Mail, Target, TrendingUp } from "lucide-react";
import { fetchDashboardSummary, type DashboardSummary } from "../api/client";

const VERDICT_COLORS: Record<string, string> = {
  block: "#ef4444",
  quarantine: "#f97316",
  warn: "#eab308",
  allow: "#22c55e",
};

const THREAT_COLORS = [
  "#ef4444",
  "#f97316",
  "#eab308",
  "#3b82f6",
  "#8b5cf6",
  "#ec4899",
  "#06b6d4",
  "#22c55e",
];

export default function PhishingDashboard() {
  const { data, isLoading } = useQuery<DashboardSummary>({
    queryKey: ["dashboard"],
    queryFn: fetchDashboardSummary,
    refetchInterval: 15_000,
  });

  if (isLoading || !data)
    return <p className="text-gray-400">Loading dashboard…</p>;

  const verdictData = Object.entries(data.verdict_breakdown).map(([name, value]) => ({
    name,
    value,
  }));
  const threatData = Object.entries(data.threat_type_breakdown).map(([name, value]) => ({
    name,
    value,
  }));

  const kpis = [
    {
      label: "Emails Processed",
      value: data.total_emails_processed,
      icon: Mail,
      color: "text-blue-400",
    },
    {
      label: "Blocked",
      value: data.emails_blocked,
      icon: ShieldAlert,
      color: "text-red-400",
    },
    {
      label: "Quarantined",
      value: data.emails_quarantined,
      icon: AlertTriangle,
      color: "text-orange-400",
    },
    {
      label: "Allowed",
      value: data.emails_allowed,
      icon: ShieldCheck,
      color: "text-green-400",
    },
    {
      label: "Detection Rate",
      value: `${data.detection_rate}%`,
      icon: Target,
      color: "text-purple-400",
    },
    {
      label: "FP Rate",
      value: `${data.false_positive_rate}%`,
      icon: TrendingUp,
      color: "text-yellow-400",
    },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Phishing Defense Dashboard</h1>

      {/* KPI cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
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
        {/* Verdict bar chart */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-4 text-sm font-semibold text-gray-300">Verdicts Breakdown</h2>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={verdictData}>
              <XAxis dataKey="name" stroke="#9ca3af" />
              <YAxis stroke="#9ca3af" allowDecimals={false} />
              <Tooltip
                contentStyle={{ backgroundColor: "#1f2937", border: "1px solid #374151" }}
              />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {verdictData.map((d) => (
                  <Cell key={d.name} fill={VERDICT_COLORS[d.name] ?? "#6366f1"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Threat type pie chart */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-4 text-sm font-semibold text-gray-300">Threat Types</h2>
          {threatData.length === 0 ? (
            <p className="text-gray-500 text-sm">No threat data yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={threatData}
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {threatData.map((_, i) => (
                    <Cell key={i} fill={THREAT_COLORS[i % THREAT_COLORS.length]} />
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

      {/* Queue status */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <p className="text-xs text-gray-400">Quarantine Queue</p>
          <p className="mt-1 text-2xl font-bold">{data.quarantine_queue_size}</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <p className="text-xs text-gray-400">Pending Reports</p>
          <p className="mt-1 text-2xl font-bold">{data.pending_reports}</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <p className="text-xs text-gray-400">Active Campaigns</p>
          <p className="mt-1 text-2xl font-bold">{data.active_campaigns}</p>
        </div>
      </div>
    </div>
  );
}
