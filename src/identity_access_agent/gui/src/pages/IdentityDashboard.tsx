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
import { ShieldAlert, Users, AlertTriangle, KeyRound, TrendingUp, Split } from "lucide-react";
import { fetchDashboardSummary, type DashboardSummary } from "../api/client";

const RISK_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

const SIGNAL_COLORS = ["#ef4444", "#f97316", "#eab308", "#3b82f6"];

export default function IdentityDashboard() {
  const { data, isLoading } = useQuery<DashboardSummary>({
    queryKey: ["dashboard"],
    queryFn: fetchDashboardSummary,
    refetchInterval: 15_000,
  });

  if (isLoading || !data)
    return <p className="text-gray-400">Loading dashboard…</p>;

  const riskData = [
    { name: "Critical", value: data.critical_risk_users, fill: RISK_COLORS.critical },
    { name: "High", value: data.high_risk_users, fill: RISK_COLORS.high },
    { name: "Medium", value: data.medium_risk_users, fill: RISK_COLORS.medium },
    { name: "Low", value: data.low_risk_users, fill: RISK_COLORS.low },
  ];

  const signalData = [
    { name: "Impossible Travel", value: data.impossible_travel_detections },
    { name: "MFA Fatigue", value: data.mfa_fatigue_detections },
    { name: "Brute Force", value: data.brute_force_detections },
    { name: "Privilege Escalation", value: data.privilege_escalation_detections },
  ];

  const kpis = [
    { label: "Events Processed", value: data.total_events_processed, icon: KeyRound, color: "text-blue-400" },
    { label: "Critical Users", value: data.critical_risk_users, icon: ShieldAlert, color: "text-red-400" },
    { label: "High Risk Users", value: data.high_risk_users, icon: AlertTriangle, color: "text-orange-400" },
    { label: "Open Alerts", value: data.open_alerts, icon: ShieldAlert, color: "text-yellow-400" },
    { label: "SoD Violations", value: data.sod_violations, icon: Split, color: "text-purple-400" },
    { label: "Mean Risk Score", value: data.mean_risk_score, icon: TrendingUp, color: "text-green-400" },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Identity & Access Monitoring Dashboard</h1>

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
        {/* Risk level distribution */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-4 text-sm font-semibold text-gray-300">Risk Level Distribution</h2>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={riskData} cx="50%" cy="50%" outerRadius={90} dataKey="value"
                label={({ name, value }) => `${name}: ${value}`}>
                {riskData.map((d) => (
                  <Cell key={d.name} fill={d.fill} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: "#1f2937", border: "1px solid #374151" }} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Threat signals bar chart */}
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-4 text-sm font-semibold text-gray-300">Threat Signal Breakdown</h2>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={signalData}>
              <XAxis dataKey="name" stroke="#9ca3af" tick={{ fontSize: 11 }} />
              <YAxis stroke="#9ca3af" allowDecimals={false} />
              <Tooltip contentStyle={{ backgroundColor: "#1f2937", border: "1px solid #374151" }} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {signalData.map((_, i) => (
                  <Cell key={i} fill={SIGNAL_COLORS[i % SIGNAL_COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top risky users */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
        <h2 className="mb-4 text-sm font-semibold text-gray-300">Top Risky Users</h2>
        {data.top_risky_users.length === 0 ? (
          <p className="text-gray-500 text-sm">No risk scores computed yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-left text-gray-400">
                  <th className="pb-2">User</th>
                  <th className="pb-2">Risk Score</th>
                </tr>
              </thead>
              <tbody>
                {data.top_risky_users.map((u) => (
                  <tr key={u.user_id} className="border-b border-gray-800/50">
                    <td className="py-2">{u.username || u.user_id}</td>
                    <td className="py-2 font-mono">{u.risk_score.toFixed(1)}</td>
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
