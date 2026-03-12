import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getIncident,
  updateIncident,
  submitFeedback,
  type Incident,
  type IncidentFeedback,
} from "../api/client";

const PRIORITY_BADGE: Record<string, string> = {
  P1: "bg-red-600 text-white",
  P2: "bg-orange-600 text-white",
  P3: "bg-yellow-600 text-black",
  P4: "bg-green-600 text-white",
};

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const { data: inc, isLoading } = useQuery<Incident>({
    queryKey: ["incident", id],
    queryFn: () => getIncident(id!),
    enabled: !!id,
  });

  const updateMut = useMutation({
    mutationFn: (d: { status?: string; assigned_analyst?: string; analyst_notes?: string }) =>
      updateIncident(id!, d),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["incident", id] }),
  });

  const [verdict, setVerdict] = useState("true_positive");
  const [comment, setComment] = useState("");

  const feedbackMut = useMutation({
    mutationFn: (fb: IncidentFeedback) => submitFeedback(id!, fb),
    onSuccess: () => {
      setComment("");
      qc.invalidateQueries({ queryKey: ["incident", id] });
    },
  });

  if (isLoading || !inc)
    return <p className="text-gray-400">Loading incident…</p>;

  return (
    <div className="space-y-6">
      {/* Back */}
      <button
        onClick={() => navigate("/incidents")}
        className="text-sm text-brand-400 hover:underline"
      >
        &larr; Back to Queue
      </button>

      {/* Header row */}
      <div className="flex flex-wrap items-center gap-4">
        <h1 className="text-2xl font-bold">{inc.incident_id}</h1>
        <span
          className={`rounded px-2 py-0.5 text-xs font-bold ${PRIORITY_BADGE[inc.priority] ?? "bg-gray-700"}`}
        >
          {inc.priority}
        </span>
        <span className="rounded bg-gray-700 px-2 py-0.5 text-xs">{inc.status}</span>
        <span className="text-xs text-gray-400">Case: {inc.case_id}</span>
      </div>

      {/* Metadata grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          { label: "Classification", value: inc.classification },
          { label: "Severity", value: inc.severity },
          { label: "Confidence", value: `${inc.confidence}%` },
          { label: "SLA Remaining", value: `${Math.round(inc.sla_remaining_seconds / 60)}m` },
          { label: "Assigned Analyst", value: inc.assigned_analyst || "—" },
          { label: "Timestamp", value: new Date(inc.timestamp).toLocaleString() },
          { label: "Alerts", value: inc.alert_ids.length },
          { label: "Entities", value: inc.entity_profiles.length },
        ].map((m) => (
          <div key={m.label} className="rounded-lg border border-gray-800 bg-gray-900 p-3">
            <p className="text-xs text-gray-400">{m.label}</p>
            <p className="mt-1 font-semibold">{m.value}</p>
          </div>
        ))}
      </div>

      {/* Triage summary */}
      {inc.triage_summary && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-2 text-sm font-semibold text-gray-300">Triage Summary</h2>
          <p className="text-sm text-gray-400">{inc.triage_summary}</p>
        </div>
      )}

      {/* MITRE info */}
      {(inc.mitre_technique_ids.length > 0 || inc.mitre_tactics.length > 0) && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-2 text-sm font-semibold text-gray-300">MITRE ATT&CK</h2>
          <div className="flex flex-wrap gap-2">
            {inc.mitre_tactics.map((t) => (
              <span key={t} className="rounded bg-blue-900/50 px-2 py-0.5 text-xs text-blue-300">
                {t}
              </span>
            ))}
            {inc.mitre_technique_ids.map((t) => (
              <span key={t} className="rounded bg-indigo-900/50 px-2 py-0.5 text-xs text-indigo-300">
                {t}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Alert IDs */}
      {inc.alert_ids.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-2 text-sm font-semibold text-gray-300">
            Correlated Alerts ({inc.alert_ids.length})
          </h2>
          <div className="flex flex-wrap gap-2">
            {inc.alert_ids.map((a) => (
              <span key={a} className="rounded bg-gray-800 px-2 py-0.5 font-mono text-xs">
                {a}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Timeline */}
      {inc.timeline.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-2 text-sm font-semibold text-gray-300">Timeline</h2>
          <div className="space-y-2">
            {inc.timeline.map((evt, i) => (
              <div key={i} className="flex gap-3 text-sm">
                <span className="text-xs text-gray-500">
                  {(evt as Record<string, string>).timestamp ?? ""}
                </span>
                <span className="text-gray-300">
                  {(evt as Record<string, string>).event ?? JSON.stringify(evt)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex flex-wrap gap-3">
        <button
          className="rounded bg-purple-600 px-4 py-2 text-sm font-medium hover:bg-purple-500"
          onClick={() => updateMut.mutate({ status: "assigned", assigned_analyst: "analyst-1" })}
        >
          Assign
        </button>
        <button
          className="rounded bg-red-600 px-4 py-2 text-sm font-medium hover:bg-red-500"
          onClick={() => updateMut.mutate({ status: "escalated" })}
        >
          Escalate
        </button>
        <button
          className="rounded bg-green-600 px-4 py-2 text-sm font-medium hover:bg-green-500"
          onClick={() => updateMut.mutate({ status: "resolved" })}
        >
          Resolve
        </button>
        <button
          className="rounded bg-gray-700 px-4 py-2 text-sm font-medium hover:bg-gray-600"
          onClick={() => updateMut.mutate({ status: "false_positive" })}
        >
          False Positive
        </button>
      </div>

      {/* Feedback form */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
        <h2 className="mb-3 text-sm font-semibold text-gray-300">Submit Feedback</h2>
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label className="mb-1 block text-xs text-gray-400">Verdict</label>
            <select
              className="rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm"
              value={verdict}
              onChange={(e) => setVerdict(e.target.value)}
            >
              <option value="true_positive">True Positive</option>
              <option value="false_positive">False Positive</option>
              <option value="needs_tuning">Needs Tuning</option>
              <option value="reclassified">Reclassified</option>
            </select>
          </div>
          <div className="flex-1">
            <label className="mb-1 block text-xs text-gray-400">Comment</label>
            <input
              className="w-full rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              placeholder="Optional comment…"
            />
          </div>
          <button
            className="rounded bg-brand-600 px-4 py-1.5 text-sm font-medium hover:bg-brand-500"
            onClick={() =>
              feedbackMut.mutate({
                analyst_id: "analyst-1",
                verdict,
                comment: comment || undefined,
              })
            }
          >
            Submit
          </button>
        </div>
      </div>
    </div>
  );
}
