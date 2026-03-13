import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchReportedEmails, reviewReportedEmail, type ReportedEmail } from "../api/client";

const VERDICT_BADGE: Record<string, string> = {
  phishing: "bg-red-600 text-white",
  suspicious: "bg-orange-600 text-white",
  clean: "bg-green-600 text-white",
};

export default function ReportedEmails() {
  const qc = useQueryClient();
  const [processedFilter, setProcessedFilter] = useState("");
  const [reviewingId, setReviewingId] = useState<string | null>(null);
  const [reviewVerdict, setReviewVerdict] = useState("phishing");
  const [reviewNotes, setReviewNotes] = useState("");

  const params = processedFilter ? `processed=${processedFilter}` : undefined;

  const { data, isLoading } = useQuery<ReportedEmail[]>({
    queryKey: ["reported", processedFilter],
    queryFn: () => fetchReportedEmails(params),
    refetchInterval: 15_000,
  });

  const reviewMut = useMutation({
    mutationFn: (id: string) =>
      reviewReportedEmail(id, {
        analyst_id: "analyst-1",
        verdict: reviewVerdict,
        notes: reviewNotes,
      }),
    onSuccess: () => {
      setReviewingId(null);
      setReviewNotes("");
      qc.invalidateQueries({ queryKey: ["reported"] });
    },
  });

  const items = data ?? [];

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Reported Email Queue</h1>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select
          className="rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm"
          value={processedFilter}
          onChange={(e) => setProcessedFilter(e.target.value)}
        >
          <option value="">All</option>
          <option value="false">Pending</option>
          <option value="true">Processed</option>
        </select>
      </div>

      {isLoading ? (
        <p className="text-gray-400">Loading…</p>
      ) : items.length === 0 ? (
        <p className="text-gray-500">No reported emails found.</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-gray-800">
          <table className="w-full text-sm">
            <thead className="border-b border-gray-800 bg-gray-900">
              <tr>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Subject</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Sender</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Reporter</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Reported At</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Status</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Verdict</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {items.map((item) => (
                <tr key={item.report_id} className="hover:bg-gray-800/50">
                  <td className="px-4 py-3 max-w-[200px] truncate">{item.subject}</td>
                  <td className="px-4 py-3 text-gray-400">{item.sender}</td>
                  <td className="px-4 py-3 text-gray-400">{item.reporter_email}</td>
                  <td className="px-4 py-3 text-xs text-gray-400">
                    {new Date(item.reported_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-medium ${
                        item.processed ? "bg-green-600" : "bg-yellow-600 text-black"
                      }`}
                    >
                      {item.processed ? "Processed" : "Pending"}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {item.verdict ? (
                      <span
                        className={`rounded px-2 py-0.5 text-xs font-bold ${VERDICT_BADGE[item.verdict] ?? "bg-gray-700"}`}
                      >
                        {item.verdict}
                      </span>
                    ) : (
                      <span className="text-gray-500">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {!item.processed && (
                      <button
                        className="rounded bg-brand-600 px-2 py-1 text-xs hover:bg-brand-500"
                        onClick={() => setReviewingId(item.report_id)}
                      >
                        Review
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Review modal */}
      {reviewingId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="w-full max-w-md rounded-xl border border-gray-700 bg-gray-900 p-6 space-y-4">
            <h2 className="text-lg font-semibold">Review Report</h2>
            <div>
              <label className="mb-1 block text-xs text-gray-400">Verdict</label>
              <select
                className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm"
                value={reviewVerdict}
                onChange={(e) => setReviewVerdict(e.target.value)}
              >
                <option value="phishing">Phishing</option>
                <option value="suspicious">Suspicious</option>
                <option value="clean">Clean</option>
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-400">Notes</label>
              <textarea
                className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm"
                rows={3}
                value={reviewNotes}
                onChange={(e) => setReviewNotes(e.target.value)}
                placeholder="Analyst notes…"
              />
            </div>
            <div className="flex gap-3 justify-end">
              <button
                className="rounded bg-gray-700 px-4 py-2 text-sm hover:bg-gray-600"
                onClick={() => setReviewingId(null)}
              >
                Cancel
              </button>
              <button
                className="rounded bg-brand-600 px-4 py-2 text-sm font-medium hover:bg-brand-500"
                onClick={() => reviewMut.mutate(reviewingId)}
              >
                Submit Review
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
