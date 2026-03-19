import { useQuery } from "@tanstack/react-query";
import { getPolicyVerdicts } from "../api/client";

const VERDICT_COLOR: Record<string, string> = {
  block: "text-red-400",
  warn: "text-yellow-400",
  pass: "text-green-400",
};

export default function PolicyGates() {
  const { data, isLoading } = useQuery({ queryKey: ["policy"], queryFn: getPolicyVerdicts });
  const items = Array.isArray(data) ? data : (data?.items ?? []);

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Policy Gates</h1>
      {isLoading ? (
        <p className="text-gray-400">Loading…</p>
      ) : (
        <div className="flex flex-col gap-3">
          {items.map((v: Record<string, unknown>, i: number) => (
            <div key={String(v.verdict_id ?? i)} className="bg-gray-800 rounded-lg p-4">
              <div className="flex justify-between items-center">
                <span className="font-mono text-xs text-gray-400">{String(v.scan_id ?? "")}</span>
                <span className={`font-bold uppercase text-sm ${VERDICT_COLOR[String(v.decision)] ?? ""}`}>
                  {String(v.decision ?? "")}
                </span>
              </div>
              <p className="text-sm mt-1 text-gray-300">{String(v.reason ?? "")}</p>
            </div>
          ))}
          {items.length === 0 && (
            <p className="text-gray-500">No policy verdicts yet — trigger a scan to generate one.</p>
          )}
        </div>
      )}
    </div>
  );
}
