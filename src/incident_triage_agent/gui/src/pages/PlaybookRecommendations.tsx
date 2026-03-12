import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { BookOpen, ChevronDown, ChevronRight } from "lucide-react";
import {
  fetchIncidents,
  fetchPlaybooks,
  type PaginatedIncidents,
  type PlaybookRecommendation,
} from "../api/client";

const ACTION_BADGE: Record<string, string> = {
  investigate: "bg-blue-600",
  contain: "bg-red-600",
  remediate: "bg-orange-600",
  recover: "bg-green-600",
};

export default function PlaybookRecommendations() {
  const [selectedId, setSelectedId] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const { data: incidents } = useQuery<PaginatedIncidents>({
    queryKey: ["incidents-pb"],
    queryFn: () => fetchIncidents("page=1&page_size=50"),
  });

  const { data: playbooks, isLoading } = useQuery<PlaybookRecommendation[]>({
    queryKey: ["playbooks", selectedId],
    queryFn: () => fetchPlaybooks(selectedId),
    enabled: !!selectedId,
  });

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Playbook Recommendations</h1>

      {/* Incident selector */}
      <div>
        <label className="mb-1 block text-xs text-gray-400">Select Incident</label>
        <select
          className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm"
          value={selectedId}
          onChange={(e) => {
            setSelectedId(e.target.value);
            setExpanded(null);
          }}
        >
          <option value="">— Choose an incident —</option>
          {incidents?.items.map((inc) => (
            <option key={inc.incident_id} value={inc.incident_id}>
              {inc.incident_id} — {inc.classification} ({inc.priority})
            </option>
          ))}
        </select>
      </div>

      {!selectedId && (
        <p className="text-gray-500 text-sm">
          Select an incident to see recommended playbooks.
        </p>
      )}

      {isLoading && <p className="text-gray-400">Loading playbooks…</p>}

      {playbooks && (
        <div className="space-y-4">
          {playbooks.length === 0 ? (
            <p className="text-gray-500 text-sm">No playbooks recommended.</p>
          ) : (
            playbooks.map((pb) => (
              <div
                key={pb.playbook_id}
                className="rounded-xl border border-gray-800 bg-gray-900"
              >
                {/* Header */}
                <button
                  className="flex w-full items-center gap-3 p-4 text-left"
                  onClick={() =>
                    setExpanded(expanded === pb.playbook_id ? null : pb.playbook_id)
                  }
                >
                  {expanded === pb.playbook_id ? (
                    <ChevronDown className="h-4 w-4 text-gray-400" />
                  ) : (
                    <ChevronRight className="h-4 w-4 text-gray-400" />
                  )}
                  <BookOpen className="h-5 w-5 text-brand-400" />
                  <div className="flex-1">
                    <p className="font-semibold">{pb.name}</p>
                    <p className="text-xs text-gray-400">{pb.description}</p>
                  </div>
                  <span
                    className={`rounded px-2 py-0.5 text-xs font-medium ${ACTION_BADGE[pb.action_type] ?? "bg-gray-700"}`}
                  >
                    {pb.action_type}
                  </span>
                  <span className="rounded bg-gray-700 px-2 py-0.5 text-xs">
                    {Math.round(pb.confidence * 100)}% conf.
                  </span>
                </button>

                {/* Expanded steps */}
                {expanded === pb.playbook_id && (
                  <div className="border-t border-gray-800 px-4 pb-4 pt-3">
                    <h3 className="mb-2 text-sm font-semibold text-gray-300">
                      Steps ({pb.steps.length})
                    </h3>
                    <ol className="list-inside list-decimal space-y-1 text-sm text-gray-400">
                      {pb.steps.map((step, i) => (
                        <li key={i}>{step}</li>
                      ))}
                    </ol>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
