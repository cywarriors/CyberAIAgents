import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { getFindings } from "../api/client";

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-green-400",
};

export default function Findings() {
  const [type, setType] = useState("");
  const [severity, setSeverity] = useState("");
  const { data, isLoading } = useQuery({
    queryKey: ["findings", type, severity],
    queryFn: () => getFindings({ finding_type: type, severity }),
  });
  const items = data?.items ?? [];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Security Findings</h1>
      <div className="flex gap-4 mb-4">
        <select
          className="bg-gray-800 rounded px-3 py-1 text-sm"
          value={type}
          onChange={(e) => setType(e.target.value)}
        >
          <option value="">All Types</option>
          <option value="sast">SAST</option>
          <option value="secret">Secrets</option>
          <option value="sca">SCA</option>
        </select>
        <select
          className="bg-gray-800 rounded px-3 py-1 text-sm"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>
      {isLoading ? (
        <p className="text-gray-400">Loading…</p>
      ) : (
        <div className="overflow-auto rounded border border-gray-700">
          <table className="w-full text-sm">
            <thead className="bg-gray-800">
              <tr>
                {["Type", "File", "Line", "Severity", "Description", "CWE"].map((h) => (
                  <th key={h} className="px-4 py-2 text-left text-gray-300">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((f: Record<string, unknown>, i: number) => (
                <tr key={String(f.finding_id ?? i)} className="border-t border-gray-700 hover:bg-gray-800">
                  <td className="px-4 py-2">{String(f.type ?? "")}</td>
                  <td className="px-4 py-2 font-mono text-xs">{String(f.file_path ?? "")}</td>
                  <td className="px-4 py-2">{String(f.line_number ?? "")}</td>
                  <td className={`px-4 py-2 font-semibold ${SEV_COLORS[String(f.severity)] ?? ""}`}>
                    {String(f.severity ?? "")}
                  </td>
                  <td className="px-4 py-2 max-w-xs truncate">{String(f.description ?? f.secret_type ?? "")}</td>
                  <td className="px-4 py-2 font-mono text-xs">{String(f.cwe_id ?? "")}</td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-gray-500">No findings</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
