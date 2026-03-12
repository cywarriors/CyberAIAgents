import { useQuery } from "@tanstack/react-query";
import { fetchCoverage } from "../api/client";
import { Shield, CheckCircle, XCircle } from "lucide-react";

const TACTIC_COLORS: Record<string, string> = {
  "Initial Access": "bg-red-900/50 border-red-700",
  "Execution": "bg-orange-900/50 border-orange-700",
  "Persistence": "bg-yellow-900/50 border-yellow-700",
  "Privilege Escalation": "bg-amber-900/50 border-amber-700",
  "Defense Evasion": "bg-purple-900/50 border-purple-700",
  "Credential Access": "bg-pink-900/50 border-pink-700",
  "Lateral Movement": "bg-indigo-900/50 border-indigo-700",
  "Command and Control": "bg-blue-900/50 border-blue-700",
  "Exfiltration": "bg-cyan-900/50 border-cyan-700",
  "Impact": "bg-rose-900/50 border-rose-700",
};

export default function DetectionCoverage() {
  const { data, isLoading } = useQuery({
    queryKey: ["coverage"],
    queryFn: fetchCoverage,
  });

  if (isLoading || !data) return <p className="text-gray-400">Loading coverage…</p>;

  // Group techniques by tactic
  const byTactic: Record<string, typeof data.techniques> = {};
  for (const t of data.techniques) {
    (byTactic[t.tactic] ??= []).push(t);
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">ATT&CK Detection Coverage</h1>
        <div className="flex items-center gap-4 text-sm text-gray-400">
          <span>{data.covered_techniques}/{data.total_techniques} techniques covered</span>
          <span className="rounded-full bg-brand-600/20 px-3 py-1 text-brand-400 font-medium">
            {data.coverage_percentage}%
          </span>
        </div>
      </div>

      {/* Coverage heatmap grid */}
      <div className="space-y-4">
        {Object.entries(byTactic).map(([tactic, techniques]) => (
          <div key={tactic}>
            <h3 className="mb-2 text-sm font-semibold text-gray-300">{tactic}</h3>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {techniques.map((t) => (
                <div
                  key={t.technique_id}
                  className={`flex items-center gap-3 rounded-lg border p-3 ${
                    t.covered
                      ? TACTIC_COLORS[tactic] ?? "bg-gray-800 border-gray-700"
                      : "border-gray-800 bg-gray-900 opacity-60"
                  }`}
                >
                  {t.covered ? (
                    <CheckCircle className="h-4 w-4 shrink-0 text-green-400" />
                  ) : (
                    <XCircle className="h-4 w-4 shrink-0 text-gray-600" />
                  )}
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-white">{t.technique_name}</p>
                    <p className="text-xs text-gray-400">
                      {t.technique_id} &bull; {t.rule_count} rules &bull; {t.alert_count} alerts
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Gap analysis */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
        <h2 className="mb-3 font-semibold text-gray-300 flex items-center gap-2">
          <Shield className="h-4 w-4" /> Coverage Gaps
        </h2>
        <div className="space-y-2">
          {data.techniques
            .filter((t) => !t.covered)
            .map((t) => (
              <div key={t.technique_id} className="flex items-center justify-between rounded-lg bg-gray-800 px-4 py-2">
                <span className="text-sm text-white">{t.technique_id} — {t.technique_name}</span>
                <span className="text-xs text-gray-500">{t.tactic}</span>
              </div>
            ))}
          {data.techniques.filter((t) => !t.covered).length === 0 && (
            <p className="text-sm text-green-400">Full coverage achieved!</p>
          )}
        </div>
      </div>
    </div>
  );
}
