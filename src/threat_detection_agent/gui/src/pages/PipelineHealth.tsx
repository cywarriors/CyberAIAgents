import { useQuery } from "@tanstack/react-query";
import { fetchPipelineHealth } from "../api/client";
import { HeartPulse, Database, Server } from "lucide-react";

function formatUptime(s: number) {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${h}h ${m}m`;
}

export default function PipelineHealth() {
  const { data, isLoading } = useQuery({
    queryKey: ["pipeline"],
    queryFn: fetchPipelineHealth,
    refetchInterval: 10_000,
  });

  if (isLoading || !data) return <p className="text-gray-400">Loading pipeline health…</p>;

  const connections = [
    { name: "Kafka", ok: data.kafka_connected },
    { name: "Redis", ok: data.redis_connected },
    { name: "PostgreSQL", ok: data.postgres_connected },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Pipeline Health</h1>

      {/* Status overview */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="flex items-center gap-2 text-gray-400">
            <HeartPulse className="h-4 w-4" />
            <span className="text-xs uppercase">Status</span>
          </div>
          <p className={`mt-2 text-xl font-bold ${data.status === "healthy" ? "text-green-400" : "text-red-400"}`}>
            {data.status}
          </p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="flex items-center gap-2 text-gray-400">
            <Server className="h-4 w-4" />
            <span className="text-xs uppercase">Uptime</span>
          </div>
          <p className="mt-2 text-xl font-bold text-white">{formatUptime(data.uptime_seconds)}</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="flex items-center gap-2 text-gray-400">
            <span className="text-xs uppercase">Nodes</span>
          </div>
          <p className="mt-2 text-xl font-bold text-brand-500">{data.nodes.length}</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="flex items-center gap-2 text-gray-400">
            <span className="text-xs uppercase">Queue Depth</span>
          </div>
          <p className="mt-2 text-xl font-bold text-white">{data.queue_depth}</p>
        </div>
      </div>

      {/* Node grid */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
        <h2 className="mb-4 font-semibold text-gray-300">Pipeline Nodes</h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {data.nodes.map((n) => (
            <div key={n.node_name} className="rounded-lg border border-gray-700 bg-gray-800 p-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-white">{n.node_name}</span>
                <span className={`h-2.5 w-2.5 rounded-full ${n.status === "healthy" ? "bg-green-400" : "bg-red-400"}`} />
              </div>
              <div className="mt-2 text-xs text-gray-400 space-y-0.5">
                <p>Processed: {n.events_processed}</p>
                <p>Errors: {n.errors}</p>
                <p>Latency: {n.avg_latency_ms.toFixed(1)}ms</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Service connections */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
        <h2 className="mb-4 font-semibold text-gray-300">Service Connections</h2>
        <div className="grid gap-3 sm:grid-cols-3">
          {connections.map((c) => (
            <div key={c.name} className="flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-800 px-4 py-3">
              <Database className="h-4 w-4 text-gray-400" />
              <span className="text-sm text-white">{c.name}</span>
              <span className={`ml-auto h-2.5 w-2.5 rounded-full ${c.ok ? "bg-green-400" : "bg-red-400"}`} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
