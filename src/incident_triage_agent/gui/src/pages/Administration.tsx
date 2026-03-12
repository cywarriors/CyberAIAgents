import { useQuery } from "@tanstack/react-query";
import { CheckCircle, XCircle } from "lucide-react";
import { fetchDashboardSummary, type DashboardSummary } from "../api/client";

export default function Administration() {
  const { data, isLoading } = useQuery<DashboardSummary>({
    queryKey: ["admin-health"],
    queryFn: fetchDashboardSummary,
    refetchInterval: 10_000,
  });

  if (isLoading || !data)
    return <p className="text-gray-400">Loading…</p>;

  const services = [
    { name: "BFF API", connected: true },
    { name: "Kafka", connected: false },
    { name: "Redis", connected: false },
    { name: "PostgreSQL", connected: false },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Administration</h1>

      {/* System overview */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <p className="text-xs text-gray-400">Open Incidents</p>
          <p className="mt-1 text-2xl font-bold">{data.open_incidents}</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <p className="text-xs text-gray-400">Incidents Today</p>
          <p className="mt-1 text-2xl font-bold">{data.incidents_today}</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <p className="text-xs text-gray-400">SLA Compliance</p>
          <p className="mt-1 text-2xl font-bold">{data.sla_compliance_pct}%</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <p className="text-xs text-gray-400">Escalation Rate</p>
          <p className="mt-1 text-2xl font-bold">{data.escalation_rate}%</p>
        </div>
      </div>

      {/* Service connections */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
        <h2 className="mb-4 text-sm font-semibold text-gray-300">Service Connections</h2>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {services.map((s) => (
            <div
              key={s.name}
              className="flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2"
            >
              {s.connected ? (
                <CheckCircle className="h-4 w-4 text-green-400" />
              ) : (
                <XCircle className="h-4 w-4 text-red-400" />
              )}
              <span className="text-sm">{s.name}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Priority breakdown */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
        <h2 className="mb-4 text-sm font-semibold text-gray-300">Priority Breakdown</h2>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {(["P1", "P2", "P3", "P4"] as const).map((p) => (
            <div key={p} className="rounded-lg border border-gray-700 bg-gray-800 p-3 text-center">
              <p className="text-xs text-gray-400">{p}</p>
              <p className="mt-1 text-xl font-bold">
                {data.priority_breakdown[p] ?? 0}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
