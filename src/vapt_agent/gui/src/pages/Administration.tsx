import { useQuery } from "@tanstack/react-query";
import { fetchHealth } from "../api/client";
import { Activity, Cpu, Database, Server } from "lucide-react";

function formatUptime(s: number) {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${h}h ${m}m`;
}

export default function Administration() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["admin-health"],
    queryFn: fetchHealth,
    refetchInterval: 10_000,
  });

  if (isLoading) return <p className="text-gray-400">Loading system health…</p>;
  if (error) return <p className="text-red-400">Error loading system health</p>;
  if (!data) return null;

  const connections = [
    { name: "Kafka", ok: data.kafka_connected },
    { name: "Redis", ok: data.redis_connected },
    { name: "PostgreSQL", ok: data.postgres_connected },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Administration</h1>

      {/* Status overview */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="flex items-center gap-2 text-gray-400">
            <Activity className="h-4 w-4" />
            <span className="text-xs uppercase">Status</span>
          </div>
          <p
            className={`mt-2 text-xl font-bold ${
              data.status === "healthy" ? "text-green-400" : "text-red-400"
            }`}
          >
            {data.status}
          </p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="flex items-center gap-2 text-gray-400">
            <Cpu className="h-4 w-4" />
            <span className="text-xs uppercase">Uptime</span>
          </div>
          <p className="mt-2 text-xl font-bold text-white">
            {formatUptime(data.uptime_seconds)}
          </p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="flex items-center gap-2 text-gray-400">
            <Server className="h-4 w-4" />
            <span className="text-xs uppercase">Scanner Engines</span>
          </div>
          <p className="mt-2 text-xl font-bold text-brand-500">
            {Object.keys(data.scanner_engines).length}
          </p>
        </div>
      </div>

      {/* Scanner engines */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
        <h2 className="mb-4 font-semibold text-gray-300">Scanner Engines</h2>
        <div className="flex flex-wrap gap-2">
          {Object.entries(data.scanner_engines).map(([name, status]) => (
            <span
              key={name}
              className={`rounded-full border px-3 py-1 text-sm ${
                status === "active"
                  ? "border-green-700 bg-green-900 text-green-300"
                  : "border-gray-700 bg-gray-800 text-gray-400"
              }`}
            >
              {name}: {status}
            </span>
          ))}
        </div>
      </div>

      {/* Service connections */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
        <h2 className="mb-4 font-semibold text-gray-300">
          Service Connections
        </h2>
        <div className="grid gap-3 sm:grid-cols-3">
          {connections.map((c) => (
            <div
              key={c.name}
              className="flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-800 px-4 py-3"
            >
              <Database className="h-4 w-4 text-gray-400" />
              <span className="text-sm text-white">{c.name}</span>
              <span
                className={`ml-auto h-2.5 w-2.5 rounded-full ${
                  c.ok ? "bg-green-400" : "bg-red-400"
                }`}
              />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
