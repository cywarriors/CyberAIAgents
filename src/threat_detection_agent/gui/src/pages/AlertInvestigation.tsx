import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchAlerts, updateAlert, submitFeedback, type Alert } from "../api/client";
import { AlertTriangle, MessageSquare, ChevronRight } from "lucide-react";

const SEV_BADGE: Record<string, string> = {
  Critical: "bg-red-900 text-red-300",
  High: "bg-orange-900 text-orange-300",
  Medium: "bg-yellow-900 text-yellow-300",
  Low: "bg-green-900 text-green-300",
  Info: "bg-blue-900 text-blue-300",
};

export default function AlertInvestigation() {
  const qc = useQueryClient();
  const [severity, setSeverity] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [feedbackVerdict, setFeedbackVerdict] = useState("true_positive");
  const [feedbackComment, setFeedbackComment] = useState("");

  const params = new URLSearchParams();
  if (severity) params.set("severity", severity);
  params.set("page", String(page));
  params.set("page_size", "20");

  const { data, isLoading } = useQuery({
    queryKey: ["alerts", severity, page],
    queryFn: () => fetchAlerts(params.toString()),
    refetchInterval: 10_000,
  });

  const statusMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      updateAlert(id, { status } as Partial<Alert>),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alerts"] });
    },
  });

  const feedbackMut = useMutation({
    mutationFn: ({ id, d }: { id: string; d: { analyst_id: string; verdict: string; comment?: string } }) =>
      submitFeedback(id, d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alerts"] });
      setFeedbackComment("");
    },
  });

  if (isLoading) return <p className="text-gray-400">Loading alerts…</p>;

  return (
    <div className="flex gap-6">
      {/* Alert list */}
      <div className={`space-y-4 ${selected ? "w-1/2" : "w-full"}`}>
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Alert Investigation</h1>
          <select
            value={severity}
            onChange={(e) => { setSeverity(e.target.value); setPage(1); }}
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white focus:border-brand-500 focus:outline-none"
          >
            <option value="">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Info">Info</option>
          </select>
        </div>

        <div className="space-y-2">
          {data?.items.map((a) => (
            <button
              key={a.alert_id}
              onClick={() => setSelected(a)}
              className={`flex w-full items-center justify-between rounded-xl border p-4 text-left transition-colors ${
                selected?.alert_id === a.alert_id
                  ? "border-brand-500 bg-gray-800"
                  : "border-gray-800 bg-gray-900 hover:bg-gray-800"
              }`}
            >
              <div className="flex items-center gap-3">
                <AlertTriangle className="h-4 w-4 text-gray-400" />
                <div>
                  <p className="text-sm font-medium text-white">{a.description || a.alert_id}</p>
                  <p className="text-xs text-gray-500">
                    {a.source_type} &bull; {new Date(a.timestamp).toLocaleString()}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${SEV_BADGE[a.severity] ?? "bg-gray-700 text-gray-300"}`}>
                  {a.severity}
                </span>
                <ChevronRight className="h-4 w-4 text-gray-600" />
              </div>
            </button>
          ))}
          {(!data || data.items.length === 0) && (
            <p className="py-8 text-center text-gray-500">No alerts found.</p>
          )}
        </div>

        {/* Pagination */}
        {data && data.pages > 1 && (
          <div className="flex items-center justify-center gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage(page - 1)}
              className="rounded bg-gray-800 px-3 py-1 text-sm text-gray-300 disabled:opacity-40"
            >
              Prev
            </button>
            <span className="text-xs text-gray-500">
              {page} / {data.pages}
            </span>
            <button
              disabled={page >= data.pages}
              onClick={() => setPage(page + 1)}
              className="rounded bg-gray-800 px-3 py-1 text-sm text-gray-300 disabled:opacity-40"
            >
              Next
            </button>
          </div>
        )}
      </div>

      {/* Detail panel */}
      {selected && (
        <div className="w-1/2 space-y-4 rounded-xl border border-gray-800 bg-gray-900 p-5">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold text-white">{selected.alert_id}</h2>
            <button onClick={() => setSelected(null)} className="text-xs text-gray-500 hover:text-white">
              Close
            </button>
          </div>

          <p className="text-sm text-gray-300">{selected.description}</p>

          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <span className="text-xs text-gray-500">Severity</span>
              <p className="text-white">{selected.severity}</p>
            </div>
            <div>
              <span className="text-xs text-gray-500">Confidence</span>
              <p className="text-white">{selected.confidence}%</p>
            </div>
            <div>
              <span className="text-xs text-gray-500">Status</span>
              <p className="text-white">{selected.status}</p>
            </div>
            <div>
              <span className="text-xs text-gray-500">Source</span>
              <p className="text-white">{selected.source_type}</p>
            </div>
          </div>

          {/* MITRE */}
          {selected.mitre_technique_ids.length > 0 && (
            <div>
              <span className="text-xs text-gray-500">MITRE Techniques</span>
              <div className="mt-1 flex flex-wrap gap-1">
                {selected.mitre_technique_ids.map((t) => (
                  <span key={t} className="rounded bg-brand-600/20 px-2 py-0.5 text-xs text-brand-400">{t}</span>
                ))}
              </div>
            </div>
          )}

          {/* Entities */}
          {selected.entity_ids.length > 0 && (
            <div>
              <span className="text-xs text-gray-500">Entities</span>
              <div className="mt-1 flex flex-wrap gap-1">
                {selected.entity_ids.map((e) => (
                  <span key={e} className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-300">{e}</span>
                ))}
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-2">
            <button
              onClick={() => statusMut.mutate({ id: selected.alert_id, status: "escalated" })}
              className="rounded-lg bg-red-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-600"
            >
              Escalate
            </button>
            <button
              onClick={() => statusMut.mutate({ id: selected.alert_id, status: "investigating" })}
              className="rounded-lg bg-brand-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-brand-500"
            >
              Investigate
            </button>
            <button
              onClick={() => statusMut.mutate({ id: selected.alert_id, status: "dismissed" })}
              className="rounded-lg bg-gray-700 px-3 py-1.5 text-xs font-medium text-gray-300 hover:bg-gray-600"
            >
              Dismiss
            </button>
          </div>

          {/* Feedback */}
          <div className="border-t border-gray-800 pt-4">
            <div className="flex items-center gap-2 text-sm text-gray-400">
              <MessageSquare className="h-4 w-4" />
              <span>Analyst Feedback</span>
            </div>
            <div className="mt-2 flex gap-2">
              <select
                value={feedbackVerdict}
                onChange={(e) => setFeedbackVerdict(e.target.value)}
                className="rounded-lg border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-white focus:outline-none"
              >
                <option value="true_positive">True Positive</option>
                <option value="false_positive">False Positive</option>
                <option value="needs_tuning">Needs Tuning</option>
              </select>
              <input
                value={feedbackComment}
                onChange={(e) => setFeedbackComment(e.target.value)}
                placeholder="Comment…"
                className="flex-1 rounded-lg border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-white placeholder-gray-500 focus:outline-none"
              />
              <button
                onClick={() =>
                  feedbackMut.mutate({
                    id: selected.alert_id,
                    d: { analyst_id: "analyst-1", verdict: feedbackVerdict, comment: feedbackComment },
                  })
                }
                className="rounded-lg bg-brand-600 px-3 py-1 text-xs font-medium text-white hover:bg-brand-500"
              >
                Submit
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
