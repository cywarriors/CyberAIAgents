import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchFindings, type PaginatedFindings } from "../api/client";
import { ChevronLeft, ChevronRight } from "lucide-react";

const SEV_BADGE: Record<string, string> = {
  critical: "bg-red-900 text-red-300",
  high: "bg-orange-900 text-orange-300",
  medium: "bg-yellow-900 text-yellow-300",
  low: "bg-blue-900 text-blue-300",
  info: "bg-gray-700 text-gray-300",
};

export default function FindingsExplorer() {
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState("");
  const [search, setSearch] = useState("");
  const pageSize = 20;

  const params = new URLSearchParams();
  params.set("page", String(page));
  params.set("page_size", String(pageSize));
  if (severity) params.set("severity", severity);
  if (search) params.set("search", search);

  const { data, isLoading } = useQuery<PaginatedFindings>({
    queryKey: ["findings", page, severity, search],
    queryFn: () => fetchFindings(params.toString()),
  });

  const totalPages = data ? Math.max(1, Math.ceil(data.total / pageSize)) : 1;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Findings Explorer</h1>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
          placeholder="Search CVE, title…"
          className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-brand-500 focus:outline-none"
        />
        <select
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setPage(1);
          }}
          className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-brand-500 focus:outline-none"
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </div>

      {isLoading ? (
        <p className="text-gray-400">Loading findings…</p>
      ) : (
        <>
          <div className="overflow-x-auto rounded-xl border border-gray-800">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-gray-800 bg-gray-900 text-xs uppercase text-gray-500">
                <tr>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Title</th>
                  <th className="px-4 py-3">CVE</th>
                  <th className="px-4 py-3">Score</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 bg-gray-950">
                {data?.items.map((f) => (
                  <tr key={f.id} className="hover:bg-gray-900">
                    <td className="px-4 py-3">
                      <span
                        className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                          SEV_BADGE[f.severity] ?? SEV_BADGE.info
                        }`}
                      >
                        {f.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-medium text-white">{f.title}</td>
                    <td className="px-4 py-3 font-mono text-gray-400">
                      {f.cve_id ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-gray-300">{f.composite_score.toFixed(1)}</td>
                    <td className="px-4 py-3 text-gray-400">{f.status}</td>
                  </tr>
                ))}
                {data?.items.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                      No findings match your filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between text-sm text-gray-400">
            <span>
              Page {page} of {totalPages} &bull; {data?.total ?? 0} results
            </span>
            <div className="flex gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="rounded-lg border border-gray-700 p-2 hover:bg-gray-800 disabled:opacity-30"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="rounded-lg border border-gray-700 p-2 hover:bg-gray-800 disabled:opacity-30"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
