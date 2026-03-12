import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  fetchScans,
  createScan,
  abortScan,
  fetchEngagements,
  type Scan,
  type Engagement,
} from "../api/client";
import { Play, Square, Plus } from "lucide-react";

const STATUS_COLORS: Record<string, string> = {
  running: "bg-green-900 text-green-300",
  completed: "bg-blue-900 text-blue-300",
  aborted: "bg-red-900 text-red-300",
  failed: "bg-red-900 text-red-300",
};

export default function ScanMonitor() {
  const qc = useQueryClient();
  const { data: scans = [], isLoading } = useQuery({
    queryKey: ["scans"],
    queryFn: fetchScans,
    refetchInterval: 5_000,
  });
  const { data: engagements = [] } = useQuery({
    queryKey: ["engagements"],
    queryFn: fetchEngagements,
  });

  const startMut = useMutation({
    mutationFn: createScan,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });
  const stopMut = useMutation({
    mutationFn: abortScan,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });

  const [showForm, setShowForm] = useState(false);
  const [engId, setEngId] = useState("");
  const [targets, setTargets] = useState("");

  function handleStart() {
    if (!engId) return;
    startMut.mutate({
      engagement_id: engId,
      targets: targets
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
    });
    setShowForm(false);
    setTargets("");
  }

  if (isLoading) return <p className="text-gray-400">Loading scans…</p>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Scan Monitor</h1>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
        >
          <Plus className="h-4 w-4" /> New Scan
        </button>
      </div>

      {showForm && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5 space-y-3">
          <select
            value={engId}
            onChange={(e) => setEngId(e.target.value)}
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-brand-500 focus:outline-none"
          >
            <option value="">Select engagement…</option>
            {engagements.map((en: Engagement) => (
              <option key={en.id} value={en.id}>
                {en.name}
              </option>
            ))}
          </select>
          <input
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            placeholder="Targets (comma-separated)"
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-brand-500 focus:outline-none"
          />
          <button
            onClick={handleStart}
            disabled={startMut.isPending || !engId}
            className="flex items-center gap-2 rounded-lg bg-green-700 px-4 py-2 text-sm font-medium text-white hover:bg-green-600 disabled:opacity-50"
          >
            <Play className="h-4 w-4" />{" "}
            {startMut.isPending ? "Starting…" : "Start Scan"}
          </button>
        </div>
      )}

      <div className="space-y-3">
        {scans.map((s: Scan) => (
          <div
            key={s.id}
            className="flex items-center justify-between rounded-xl border border-gray-800 bg-gray-900 p-4"
          >
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="font-medium text-white">
                  {s.engines.join(", ")}
                </span>
                <span
                  className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                    STATUS_COLORS[s.status] ?? "bg-gray-700 text-gray-300"
                  }`}
                >
                  {s.status}
                </span>
              </div>
              <p className="text-xs text-gray-500">
                Targets: {s.targets.join(", ")} &bull; Started:{" "}
                {new Date(s.started_at).toLocaleString()}
              </p>
            </div>

            <div className="flex items-center gap-3">
              {/* Progress bar */}
              <div className="h-2 w-32 overflow-hidden rounded-full bg-gray-800">
                <div
                  className="h-full rounded-full bg-brand-500 transition-all"
                  style={{ width: `${s.progress}%` }}
                />
              </div>
              <span className="text-xs text-gray-400">{s.progress}%</span>

              {s.status === "running" && (
                <button
                  onClick={() => stopMut.mutate(s.id)}
                  className="rounded-lg p-2 text-gray-400 hover:bg-red-900 hover:text-red-300"
                  aria-label="Abort scan"
                >
                  <Square className="h-4 w-4" />
                </button>
              )}
            </div>
          </div>
        ))}
        {scans.length === 0 && (
          <p className="py-8 text-center text-gray-500">
            No scans yet. Start a new scan above.
          </p>
        )}
      </div>
    </div>
  );
}
