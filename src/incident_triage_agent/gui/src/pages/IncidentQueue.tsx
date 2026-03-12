import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  fetchIncidents,
  updateIncident,
  type PaginatedIncidents,
  type Incident,
} from "../api/client";

const PRIORITY_BADGE: Record<string, string> = {
  P1: "bg-red-600 text-white",
  P2: "bg-orange-600 text-white",
  P3: "bg-yellow-600 text-black",
  P4: "bg-green-600 text-white",
};

const STATUS_BADGE: Record<string, string> = {
  new: "bg-blue-600",
  triaging: "bg-yellow-600 text-black",
  escalated: "bg-red-600",
  assigned: "bg-purple-600",
  resolved: "bg-green-600",
  false_positive: "bg-gray-600",
};

export default function IncidentQueue() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [page, setPage] = useState(1);
  const [priority, setPriority] = useState("");
  const [status, setStatus] = useState("");

  const params = new URLSearchParams();
  params.set("page", String(page));
  params.set("page_size", "20");
  if (priority) params.set("priority", priority);
  if (status) params.set("status", status);

  const { data, isLoading } = useQuery<PaginatedIncidents>({
    queryKey: ["incidents", page, priority, status],
    queryFn: () => fetchIncidents(params.toString()),
    refetchInterval: 15_000,
  });

  const assignMut = useMutation({
    mutationFn: (inc: Incident) =>
      updateIncident(inc.incident_id, { status: "assigned", assigned_analyst: "analyst-1" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["incidents"] }),
  });

  const escalateMut = useMutation({
    mutationFn: (id: string) => updateIncident(id, { status: "escalated" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["incidents"] }),
  });

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Incident Queue</h1>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select
          className="rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm"
          value={priority}
          onChange={(e) => { setPriority(e.target.value); setPage(1); }}
        >
          <option value="">All Priorities</option>
          <option value="P1">P1</option>
          <option value="P2">P2</option>
          <option value="P3">P3</option>
          <option value="P4">P4</option>
        </select>
        <select
          className="rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm"
          value={status}
          onChange={(e) => { setStatus(e.target.value); setPage(1); }}
        >
          <option value="">All Statuses</option>
          <option value="new">New</option>
          <option value="triaging">Triaging</option>
          <option value="escalated">Escalated</option>
          <option value="assigned">Assigned</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>
      </div>

      {isLoading ? (
        <p className="text-gray-400">Loading…</p>
      ) : !data || data.items.length === 0 ? (
        <p className="text-gray-500">No incidents found.</p>
      ) : (
        <>
          <div className="overflow-x-auto rounded-xl border border-gray-800">
            <table className="w-full text-sm">
              <thead className="border-b border-gray-800 bg-gray-900">
                <tr>
                  <th className="px-4 py-3 text-left font-medium text-gray-400">ID</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-400">Priority</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-400">Classification</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-400">Status</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-400">Analyst</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-400">SLA</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-400">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {data.items.map((inc) => (
                  <tr
                    key={inc.incident_id}
                    className="cursor-pointer hover:bg-gray-800/50"
                    onClick={() => navigate(`/incidents/${inc.incident_id}`)}
                  >
                    <td className="px-4 py-3 font-mono text-xs">{inc.incident_id}</td>
                    <td className="px-4 py-3">
                      <span className={`rounded px-2 py-0.5 text-xs font-bold ${PRIORITY_BADGE[inc.priority] ?? "bg-gray-700"}`}>
                        {inc.priority}
                      </span>
                    </td>
                    <td className="px-4 py-3">{inc.classification}</td>
                    <td className="px-4 py-3">
                      <span className={`rounded px-2 py-0.5 text-xs font-medium ${STATUS_BADGE[inc.status] ?? "bg-gray-700"}`}>
                        {inc.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-400">
                      {inc.assigned_analyst || "—"}
                    </td>
                    <td className="px-4 py-3 text-gray-400">
                      {Math.round(inc.sla_remaining_seconds / 60)}m
                    </td>
                    <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                      <div className="flex gap-2">
                        <button
                          className="rounded bg-purple-600 px-2 py-1 text-xs hover:bg-purple-500"
                          onClick={() => assignMut.mutate(inc)}
                        >
                          Assign
                        </button>
                        <button
                          className="rounded bg-red-600 px-2 py-1 text-xs hover:bg-red-500"
                          onClick={() => escalateMut.mutate(inc.incident_id)}
                        >
                          Escalate
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between text-sm text-gray-400">
            <span>
              Page {data.page} of {data.pages} ({data.total} incidents)
            </span>
            <div className="flex gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
                className="rounded border border-gray-700 px-3 py-1 hover:bg-gray-800 disabled:opacity-40"
              >
                Prev
              </button>
              <button
                disabled={page >= data.pages}
                onClick={() => setPage((p) => p + 1)}
                className="rounded border border-gray-700 px-3 py-1 hover:bg-gray-800 disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
