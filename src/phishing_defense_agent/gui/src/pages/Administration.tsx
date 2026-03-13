import { useQuery } from "@tanstack/react-query";
import { CheckCircle, XCircle } from "lucide-react";
import {
  fetchAdminHealth,
  fetchAdminStatistics,
  type AdminHealth,
  type AdminStatistics,
} from "../api/client";

export default function Administration() {
  const { data: health, isLoading: hLoading } = useQuery<AdminHealth>({
    queryKey: ["admin-health"],
    queryFn: fetchAdminHealth,
    refetchInterval: 10_000,
  });

  const { data: stats, isLoading: sLoading } = useQuery<AdminStatistics>({
    queryKey: ["admin-stats"],
    queryFn: fetchAdminStatistics,
    refetchInterval: 15_000,
  });

  if (hLoading || sLoading)
    return <p className="text-gray-400">Loading…</p>;

  const services = [
    { name: "BFF API", connected: !!health },
    { name: "Kafka", connected: false },
    { name: "Redis", connected: false },
    { name: "PostgreSQL", connected: false },
    { name: "Email Gateway", connected: false },
    { name: "Sandbox", connected: false },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Administration</h1>

      {/* System health */}
      {health && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
            <p className="text-xs text-gray-400">Status</p>
            <p className="mt-1 text-2xl font-bold text-green-400">{health.status}</p>
          </div>
          <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
            <p className="text-xs text-gray-400">Uptime</p>
            <p className="mt-1 text-2xl font-bold">
              {Math.round(health.uptime_seconds / 60)}m
            </p>
          </div>
          <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
            <p className="text-xs text-gray-400">Version</p>
            <p className="mt-1 text-2xl font-bold">{health.version}</p>
          </div>
        </div>
      )}

      {/* Statistics */}
      {stats && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[
            { label: "Total Processed", value: stats.total_processed },
            { label: "Total Blocked", value: stats.total_blocked },
            { label: "Total Quarantined", value: stats.total_quarantined },
            { label: "Total Warned", value: stats.total_warned },
            { label: "Total Allowed", value: stats.total_allowed },
            { label: "Total Campaigns", value: stats.total_campaigns },
            { label: "Total Reports", value: stats.total_reports },
            { label: "Total IOCs", value: stats.total_iocs },
          ].map((s) => (
            <div
              key={s.label}
              className="rounded-xl border border-gray-800 bg-gray-900 p-4"
            >
              <p className="text-xs text-gray-400">{s.label}</p>
              <p className="mt-1 text-2xl font-bold">{s.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Service connections */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
        <h2 className="mb-4 text-sm font-semibold text-gray-300">Service Connections</h2>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
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
    </div>
  );
}
