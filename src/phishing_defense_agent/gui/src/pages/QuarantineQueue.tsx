import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  fetchQuarantineItems,
  releaseQuarantineItem,
  type QuarantineItem,
} from "../api/client";

const VERDICT_BADGE: Record<string, string> = {
  block: "bg-red-600 text-white",
  quarantine: "bg-orange-600 text-white",
  warn: "bg-yellow-600 text-black",
  allow: "bg-green-600 text-white",
};

const STATUS_BADGE: Record<string, string> = {
  held: "bg-orange-600",
  released: "bg-green-600",
  deleted: "bg-red-600",
  pending_review: "bg-yellow-600 text-black",
};

export default function QuarantineQueue() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("");

  const params = statusFilter ? `status=${statusFilter}` : undefined;

  const { data, isLoading } = useQuery<QuarantineItem[]>({
    queryKey: ["quarantine", statusFilter],
    queryFn: () => fetchQuarantineItems(params),
    refetchInterval: 15_000,
  });

  const releaseMut = useMutation({
    mutationFn: (id: string) =>
      releaseQuarantineItem(id, { analyst_id: "analyst-1", reason: "Legitimate email" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["quarantine"] }),
  });

  const items = data ?? [];

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Quarantine Queue</h1>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select
          className="rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="">All Statuses</option>
          <option value="held">Held</option>
          <option value="released">Released</option>
          <option value="deleted">Deleted</option>
          <option value="pending_review">Pending Review</option>
        </select>
      </div>

      {isLoading ? (
        <p className="text-gray-400">Loading…</p>
      ) : items.length === 0 ? (
        <p className="text-gray-500">No quarantined emails found.</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-gray-800">
          <table className="w-full text-sm">
            <thead className="border-b border-gray-800 bg-gray-900">
              <tr>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Subject</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Sender</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Recipient</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Score</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Verdict</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Status</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Quarantined</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {items.map((item) => (
                <tr
                  key={item.quarantine_id}
                  className="cursor-pointer hover:bg-gray-800/50"
                  onClick={() => navigate(`/verdicts/${item.email_id}`)}
                >
                  <td className="px-4 py-3 max-w-[200px] truncate">{item.subject}</td>
                  <td className="px-4 py-3 text-gray-400">{item.sender}</td>
                  <td className="px-4 py-3 text-gray-400">{item.recipient}</td>
                  <td className="px-4 py-3 font-mono">{item.risk_score}</td>
                  <td className="px-4 py-3">
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-bold ${VERDICT_BADGE[item.verdict] ?? "bg-gray-700"}`}
                    >
                      {item.verdict}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-medium ${STATUS_BADGE[item.status] ?? "bg-gray-700"}`}
                    >
                      {item.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-400">
                    {new Date(item.quarantined_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                    {item.status === "held" && (
                      <button
                        className="rounded bg-green-600 px-2 py-1 text-xs hover:bg-green-500"
                        onClick={() => releaseMut.mutate(item.quarantine_id)}
                      >
                        Release
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
