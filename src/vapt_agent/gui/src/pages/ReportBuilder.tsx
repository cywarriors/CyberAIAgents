import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  fetchReports,
  createReport,
  deleteReport,
  fetchEngagements,
  type Report,
  type Engagement,
} from "../api/client";
import { FileText, Plus, Trash2, Download } from "lucide-react";

export default function ReportBuilder() {
  const qc = useQueryClient();
  const { data: reports = [], isLoading } = useQuery({
    queryKey: ["reports"],
    queryFn: () => fetchReports(),
  });
  const { data: engagements = [] } = useQuery({
    queryKey: ["engagements"],
    queryFn: fetchEngagements,
  });

  const addMut = useMutation({
    mutationFn: createReport,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports"] }),
  });
  const delMut = useMutation({
    mutationFn: deleteReport,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports"] }),
  });

  const [showForm, setShowForm] = useState(false);
  const [engId, setEngId] = useState("");
  const [reportType, setReportType] = useState("executive");

  function handleCreate() {
    if (!engId) return;
    addMut.mutate({
      engagement_id: engId,
      report_type: reportType,
    });
    setShowForm(false);
  }

  if (isLoading) return <p className="text-gray-400">Loading reports…</p>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Report Builder</h1>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
        >
          <Plus className="h-4 w-4" /> Generate Report
        </button>
      </div>

      {showForm && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5 space-y-3">
          <select
            value={engId}
            onChange={(e) => setEngId(e.target.value)}
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-brand-500 focus:outline-none"
          >
            <option value="">Select engagement…</option>
            {engagements.map((en: Engagement) => (
              <option key={en.id} value={en.id}>
                {en.name}
              </option>
            ))}
          </select>
          <select
            value={reportType}
            onChange={(e) => setReportType(e.target.value)}
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-brand-500 focus:outline-none"
          >
            <option value="executive">Executive Summary</option>
            <option value="technical">Technical Report</option>
            <option value="compliance">Compliance Report</option>
            <option value="remediation">Remediation Plan</option>
          </select>
          <button
            onClick={handleCreate}
            disabled={addMut.isPending || !engId}
            className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
          >
            {addMut.isPending ? "Generating…" : "Generate"}
          </button>
        </div>
      )}

      <div className="space-y-3">
        {reports.map((r: Report) => (
          <div
            key={r.id}
            className="flex items-center justify-between rounded-xl border border-gray-800 bg-gray-900 p-4"
          >
            <div className="flex items-center gap-3">
              <FileText className="h-5 w-5 text-brand-500" />
              <div>
                <p className="font-medium text-white">
                  {r.report_type} Report
                </p>
                <p className="text-xs text-gray-500">
                  {r.generated_at
                    ? new Date(r.generated_at).toLocaleDateString()
                    : "Pending"}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                  r.status === "completed"
                    ? "bg-green-900 text-green-300"
                    : "bg-yellow-900 text-yellow-300"
                }`}
              >
                {r.status}
              </span>
              {r.status === "completed" && (
                <a
                  href={r.download_url}
                  className="rounded-lg p-2 text-gray-400 hover:bg-gray-800 hover:text-white"
                  aria-label="Download"
                >
                  <Download className="h-4 w-4" />
                </a>
              )}
              <button
                onClick={() => delMut.mutate(r.id)}
                className="rounded-lg p-2 text-gray-400 hover:bg-red-900 hover:text-red-300"
                aria-label="Delete report"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          </div>
        ))}
        {reports.length === 0 && (
          <p className="py-8 text-center text-gray-500">
            No reports generated yet.
          </p>
        )}
      </div>
    </div>
  );
}
