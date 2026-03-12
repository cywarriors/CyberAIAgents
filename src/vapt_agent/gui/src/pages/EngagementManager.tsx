import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  fetchEngagements,
  createEngagement,
  deleteEngagement,
  type Engagement,
} from "../api/client";
import { Plus, Trash2 } from "lucide-react";

const STATUS_BADGE: Record<string, string> = {
  draft: "bg-gray-700 text-gray-300",
  in_progress: "bg-blue-900 text-blue-300",
  completed: "bg-green-900 text-green-300",
  archived: "bg-yellow-900 text-yellow-300",
};

export default function EngagementManager() {
  const qc = useQueryClient();
  const { data: engagements = [], isLoading } = useQuery({
    queryKey: ["engagements"],
    queryFn: fetchEngagements,
  });

  const addMut = useMutation({
    mutationFn: createEngagement,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["engagements"] }),
  });

  const delMut = useMutation({
    mutationFn: deleteEngagement,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["engagements"] }),
  });

  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [scopeIps, setScopeIps] = useState("");

  function handleCreate() {
    if (!name.trim()) return;
    const ips = scopeIps
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    addMut.mutate({
      name: name.trim(),
      roe: {
        scope_ips: ips,
        scope_domains: [],
        scope_cloud_accounts: [],
        exclusions: [],
        allow_destructive: false,
        start_time: null,
        end_time: null,
      },
    });
    setName("");
    setScopeIps("");
    setShowForm(false);
  }

  if (isLoading) return <p className="text-gray-400">Loading…</p>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Engagements</h1>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
        >
          <Plus className="h-4 w-4" /> New Engagement
        </button>
      </div>

      {showForm && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5 space-y-3">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Engagement name"
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-brand-500 focus:outline-none"
          />
          <input
            value={scopeIps}
            onChange={(e) => setScopeIps(e.target.value)}
            placeholder="Scope IPs (comma-separated CIDRs)"
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-brand-500 focus:outline-none"
          />
          <button
            onClick={handleCreate}
            disabled={addMut.isPending}
            className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
          >
            {addMut.isPending ? "Creating…" : "Create"}
          </button>
        </div>
      )}

      <div className="overflow-x-auto rounded-xl border border-gray-800">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800 bg-gray-900 text-xs uppercase text-gray-500">
            <tr>
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Scope IPs</th>
              <th className="px-4 py-3">Created</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800 bg-gray-950">
            {engagements.map((e: Engagement) => (
              <tr key={e.id} className="hover:bg-gray-900">
                <td className="whitespace-nowrap px-4 py-3 font-medium text-white">
                  {e.name}
                </td>
                <td className="px-4 py-3">
                  <span
                    className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                      STATUS_BADGE[e.status] ?? "bg-gray-700 text-gray-300"
                    }`}
                  >
                    {e.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-gray-400">
                  {e.roe.scope_ips.join(", ")}
                </td>
                <td className="px-4 py-3 text-gray-400">
                  {new Date(e.created_at).toLocaleDateString()}
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => delMut.mutate(e.id)}
                    className="text-gray-500 hover:text-red-400"
                    aria-label="Delete engagement"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </td>
              </tr>
            ))}
            {engagements.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                  No engagements yet. Create one to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
