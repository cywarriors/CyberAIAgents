import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  fetchSchedules,
  createSchedule,
  deleteSchedule,
  fetchEngagements,
  type ComplianceSchedule,
} from "../api/client";
import { Plus, Trash2, ShieldCheck, Clock } from "lucide-react";

export default function ComplianceTracker() {
  const qc = useQueryClient();
  const { data: schedules = [], isLoading } = useQuery({
    queryKey: ["compliance"],
    queryFn: fetchSchedules,
  });
  const { data: engagements = [] } = useQuery({
    queryKey: ["engagements"],
    queryFn: fetchEngagements,
  });

  const addMut = useMutation({
    mutationFn: createSchedule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["compliance"] }),
  });
  const delMut = useMutation({
    mutationFn: deleteSchedule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["compliance"] }),
  });

  const [showForm, setShowForm] = useState(false);
  const [engagementId, setEngagementId] = useState("");
  const [framework, setFramework] = useState("PCI-DSS");
  const [frequency, setFrequency] = useState("weekly");

  function handleCreate() {
    addMut.mutate({
      engagement_id: engagementId,
      framework,
      frequency,
    });
    setShowForm(false);
  }

  if (isLoading) return <p className="text-gray-400">Loading schedules…</p>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Compliance Tracker</h1>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
        >
          <Plus className="h-4 w-4" /> New Schedule
        </button>
      </div>

      {showForm && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5 space-y-3">
          <select
            value={engagementId}
            onChange={(e) => setEngagementId(e.target.value)}
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-brand-500 focus:outline-none"
          >
            <option value="">Select Engagement</option>
            {engagements.map((e) => (
              <option key={e.id} value={e.id}>
                {e.name}
              </option>
            ))}
          </select>
          <select
            value={framework}
            onChange={(e) => setFramework(e.target.value)}
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-brand-500 focus:outline-none"
          >
            <option value="PCI-DSS">PCI-DSS</option>
            <option value="HIPAA">HIPAA</option>
            <option value="SOC2">SOC 2</option>
            <option value="ISO27001">ISO 27001</option>
            <option value="NIST-CSF">NIST CSF</option>
            <option value="OWASP-TOP10">OWASP Top 10</option>
          </select>
          <select
            value={frequency}
            onChange={(e) => setFrequency(e.target.value)}
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-brand-500 focus:outline-none"
          >
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
            <option value="monthly">Monthly</option>
            <option value="quarterly">Quarterly</option>
          </select>
          <button
            onClick={handleCreate}
            disabled={addMut.isPending || !engagementId}
            className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
          >
            {addMut.isPending ? "Creating…" : "Create Schedule"}
          </button>
        </div>
      )}

      <div className="space-y-3">
        {schedules.map((s: ComplianceSchedule) => (
          <div
            key={s.id}
            className="flex items-center justify-between rounded-xl border border-gray-800 bg-gray-900 p-4"
          >
            <div className="flex items-center gap-3">
              <ShieldCheck className="h-5 w-5 text-brand-500" />
              <div>
                <p className="font-medium text-white">{s.framework}</p>
                <p className="text-xs text-gray-500">
                  Frequency: {s.frequency}
                </p>
                <div className="mt-1 flex items-center gap-2 text-xs text-gray-500">
                  <Clock className="h-3 w-3" />
                  {s.next_due && (
                    <span>
                      Next: {new Date(s.next_due).toLocaleDateString()}
                    </span>
                  )}
                  {s.last_completed && (
                    <span>
                      &bull; Last:{" "}
                      {new Date(s.last_completed).toLocaleDateString()}
                    </span>
                  )}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                  s.status === "on_track"
                    ? "bg-green-900 text-green-300"
                    : "bg-yellow-900 text-yellow-300"
                }`}
              >
                {s.status}
              </span>
              <button
                onClick={() => delMut.mutate(s.id)}
                className="rounded-lg p-2 text-gray-400 hover:bg-red-900 hover:text-red-300"
                aria-label="Delete schedule"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          </div>
        ))}
        {schedules.length === 0 && (
          <p className="py-8 text-center text-gray-500">
            No compliance schedules configured.
          </p>
        )}
      </div>
    </div>
  );
}
