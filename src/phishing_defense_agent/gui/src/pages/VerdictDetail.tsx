import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getVerdict, type VerdictItem } from "../api/client";

const VERDICT_BADGE: Record<string, string> = {
  block: "bg-red-600 text-white",
  quarantine: "bg-orange-600 text-white",
  warn: "bg-yellow-600 text-black",
  allow: "bg-green-600 text-white",
};

export default function VerdictDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const { data: v, isLoading } = useQuery<VerdictItem>({
    queryKey: ["verdict", id],
    queryFn: () => getVerdict(id!),
    enabled: !!id,
  });

  if (isLoading || !v)
    return <p className="text-gray-400">Loading verdict…</p>;

  return (
    <div className="space-y-6">
      <button
        onClick={() => navigate(-1)}
        className="text-sm text-brand-400 hover:underline"
      >
        &larr; Back
      </button>

      {/* Header */}
      <div className="flex flex-wrap items-center gap-4">
        <h1 className="text-2xl font-bold">{v.subject}</h1>
        <span
          className={`rounded px-2 py-0.5 text-xs font-bold ${VERDICT_BADGE[v.verdict] ?? "bg-gray-700"}`}
        >
          {v.verdict}
        </span>
        <span className="rounded bg-gray-700 px-2 py-0.5 text-xs">{v.action}</span>
        <span className="font-mono text-sm text-gray-400">Score: {v.risk_score}</span>
      </div>

      {/* Metadata grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          { label: "From", value: v.sender },
          { label: "To", value: v.recipient },
          { label: "Timestamp", value: new Date(v.timestamp).toLocaleString() },
          { label: "Email ID", value: v.email_id },
        ].map((m) => (
          <div key={m.label} className="rounded-lg border border-gray-800 bg-gray-900 p-3">
            <p className="text-xs text-gray-400">{m.label}</p>
            <p className="mt-1 text-sm font-semibold break-all">{m.value}</p>
          </div>
        ))}
      </div>

      {/* Explanation */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
        <h2 className="mb-2 text-sm font-semibold text-gray-300">Explanation</h2>
        <p className="text-sm text-gray-400 whitespace-pre-wrap">{v.explanation}</p>
      </div>

      {/* Threat types */}
      {v.threat_types.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-2 text-sm font-semibold text-gray-300">Threat Types</h2>
          <div className="flex flex-wrap gap-2">
            {v.threat_types.map((t) => (
              <span
                key={t}
                className="rounded bg-red-900/50 px-2 py-0.5 text-xs text-red-300"
              >
                {t}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Auth result */}
      {Object.keys(v.auth_result).length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-2 text-sm font-semibold text-gray-300">Authentication Result</h2>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {Object.entries(v.auth_result).map(([key, val]) => (
              <div key={key} className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2">
                <p className="text-xs text-gray-400">{key}</p>
                <p className="mt-0.5 text-sm font-medium">{String(val)}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Content signals */}
      {v.content_signals.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-2 text-sm font-semibold text-gray-300">
            Content Signals ({v.content_signals.length})
          </h2>
          <div className="space-y-2">
            {v.content_signals.map((sig, i) => (
              <div
                key={i}
                className="flex items-center justify-between rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm"
              >
                <span className="text-gray-300">
                  {(sig as Record<string, string>).threat_type ?? JSON.stringify(sig)}
                </span>
                <span className="text-xs text-gray-400">
                  Confidence: {(sig as Record<string, number>).confidence ?? "—"}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* URL analyses */}
      {v.url_analyses.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-2 text-sm font-semibold text-gray-300">
            URL Analysis ({v.url_analyses.length})
          </h2>
          <div className="space-y-2">
            {v.url_analyses.map((u, i) => (
              <div
                key={i}
                className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm"
              >
                <p className="font-mono text-xs text-gray-300 break-all">
                  {(u as Record<string, string>).url ?? "—"}
                </p>
                <p className="text-xs text-gray-400 mt-1">
                  Verdict: {(u as Record<string, string>).verdict ?? "—"}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Attachment analyses */}
      {v.attachment_analyses.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <h2 className="mb-2 text-sm font-semibold text-gray-300">
            Attachment Analysis ({v.attachment_analyses.length})
          </h2>
          <div className="space-y-2">
            {v.attachment_analyses.map((a, i) => (
              <div
                key={i}
                className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm"
              >
                <p className="text-gray-300">
                  {(a as Record<string, string>).filename ?? "—"}
                </p>
                <p className="text-xs text-gray-400 mt-1">
                  Verdict: {(a as Record<string, string>).verdict ?? "—"}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
