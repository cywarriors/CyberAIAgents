import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  fetchIncidents,
  fetchCorrelations,
  type PaginatedIncidents,
  type CorrelationGraph,
} from "../api/client";

const NODE_COLORS: Record<string, string> = {
  incident: "bg-blue-600",
  alert: "bg-orange-500",
};

const METHOD_COLORS: Record<string, string> = {
  temporal: "text-yellow-400",
  entity: "text-green-400",
  technique: "text-purple-400",
};

export default function CorrelationViewer() {
  const [selectedId, setSelectedId] = useState("");

  const { data: incidents } = useQuery<PaginatedIncidents>({
    queryKey: ["incidents-corr"],
    queryFn: () => fetchIncidents("page=1&page_size=50"),
  });

  const { data: graph, isLoading: graphLoading } = useQuery<CorrelationGraph>({
    queryKey: ["correlations", selectedId],
    queryFn: () => fetchCorrelations(selectedId),
    enabled: !!selectedId,
  });

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Correlation Viewer</h1>

      {/* Incident selector */}
      <div>
        <label className="mb-1 block text-xs text-gray-400">Select Incident</label>
        <select
          className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm"
          value={selectedId}
          onChange={(e) => setSelectedId(e.target.value)}
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
        <p className="text-gray-500 text-sm">Select an incident to view its correlation graph.</p>
      )}

      {graphLoading && <p className="text-gray-400">Loading graph…</p>}

      {graph && (
        <div className="space-y-6">
          {/* Nodes */}
          <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
            <h2 className="mb-3 text-sm font-semibold text-gray-300">
              Nodes ({graph.nodes.length})
            </h2>
            <div className="flex flex-wrap gap-3">
              {graph.nodes.map((n) => (
                <div
                  key={n.node_id}
                  className="flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2"
                >
                  <span
                    className={`h-3 w-3 rounded-full ${NODE_COLORS[n.node_type] ?? "bg-gray-500"}`}
                  />
                  <div>
                    <p className="text-xs font-medium">{n.label}</p>
                    <p className="text-[10px] text-gray-500">
                      {n.node_type} · {n.severity}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Edges */}
          <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
            <h2 className="mb-3 text-sm font-semibold text-gray-300">
              Edges ({graph.edges.length})
            </h2>
            {graph.edges.length === 0 ? (
              <p className="text-gray-500 text-sm">No edges.</p>
            ) : (
              <div className="space-y-2">
                {graph.edges.map((e, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-3 rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm"
                  >
                    <span className="font-mono text-xs">{e.source}</span>
                    <span className="text-gray-500">&rarr;</span>
                    <span className="font-mono text-xs">{e.target}</span>
                    <span
                      className={`ml-auto text-xs font-medium ${METHOD_COLORS[e.method] ?? "text-gray-400"}`}
                    >
                      {e.method}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Legend */}
          <div className="flex flex-wrap gap-6 text-xs text-gray-400">
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-blue-600" /> Incident
            </div>
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-orange-500" /> Alert
            </div>
            {Object.entries(METHOD_COLORS).map(([m, c]) => (
              <div key={m} className="flex items-center gap-1">
                <span className={`font-medium ${c}`}>—</span> {m}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
