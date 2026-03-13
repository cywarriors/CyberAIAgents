import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { processEmails, type ProcessEmailsResponse, type VerdictItem } from "../api/client";
import { Link2, FileSearch, Loader2 } from "lucide-react";

const VERDICT_BADGE: Record<string, string> = {
  block: "bg-red-600 text-white",
  quarantine: "bg-orange-600 text-white",
  warn: "bg-yellow-600 text-black",
  allow: "bg-green-600 text-white",
};

export default function URLAttachmentAnalyzer() {
  const [rawEmail, setRawEmail] = useState(
    JSON.stringify(
      {
        message_id: "test-001",
        from: "suspicious@example.com",
        to: "user@company.com",
        subject: "Urgent: Verify your account",
        body: "Please click here to verify: https://example-phishing.com/login",
        headers: {
          "Authentication-Results": "spf=fail; dkim=fail; dmarc=fail",
        },
        attachments: [],
      },
      null,
      2,
    ),
  );
  const [results, setResults] = useState<VerdictItem[]>([]);

  const analyzeMut = useMutation({
    mutationFn: (emails: Record<string, unknown>[]) => processEmails({ emails }),
    onSuccess: (data: ProcessEmailsResponse) => {
      setResults(data.verdicts ?? []);
    },
  });

  const handleAnalyze = () => {
    try {
      const parsed = JSON.parse(rawEmail);
      const emails = Array.isArray(parsed) ? parsed : [parsed];
      analyzeMut.mutate(emails);
    } catch {
      alert("Invalid JSON input");
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">URL & Attachment Analyzer</h1>

      {/* Input area */}
      <div className="rounded-xl border border-gray-800 bg-gray-900 p-4 space-y-4">
        <div className="flex items-center gap-2 text-sm text-gray-300">
          <FileSearch className="h-4 w-4" />
          <span>Paste raw email JSON to analyze</span>
        </div>
        <textarea
          className="w-full h-64 rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm font-mono"
          value={rawEmail}
          onChange={(e) => setRawEmail(e.target.value)}
          spellCheck={false}
        />
        <button
          className="flex items-center gap-2 rounded bg-brand-600 px-4 py-2 text-sm font-medium hover:bg-brand-500 disabled:opacity-50"
          onClick={handleAnalyze}
          disabled={analyzeMut.isPending}
        >
          {analyzeMut.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Link2 className="h-4 w-4" />
          )}
          Analyze
        </button>
        {analyzeMut.isError && (
          <p className="text-sm text-red-400">
            Error: {(analyzeMut.error as Error).message}
          </p>
        )}
      </div>

      {/* Results */}
      {results.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Analysis Results ({results.length})</h2>
          {results.map((v, i) => (
            <div
              key={i}
              className="rounded-xl border border-gray-800 bg-gray-900 p-4 space-y-3"
            >
              <div className="flex flex-wrap items-center gap-3">
                <span
                  className={`rounded px-2 py-0.5 text-xs font-bold ${VERDICT_BADGE[v.verdict] ?? "bg-gray-700"}`}
                >
                  {v.verdict}
                </span>
                <span className="rounded bg-gray-700 px-2 py-0.5 text-xs">{v.action}</span>
                <span className="font-mono text-sm text-gray-400">Score: {v.risk_score}</span>
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <p className="text-xs text-gray-400">From</p>
                  <p className="text-sm">{v.sender}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-400">Subject</p>
                  <p className="text-sm">{v.subject}</p>
                </div>
              </div>

              <div>
                <p className="text-xs text-gray-400 mb-1">Explanation</p>
                <p className="text-sm text-gray-300 whitespace-pre-wrap">{v.explanation}</p>
              </div>

              {v.threat_types.length > 0 && (
                <div>
                  <p className="text-xs text-gray-400 mb-1">Threat Types</p>
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
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
