import { useQuery } from "@tanstack/react-query";
import { getScans, triggerScan } from "../api/client";

export default function Scans() {
  const { data, isLoading, refetch } = useQuery({ queryKey: ["scans"], queryFn: getScans });
  const scans = Array.isArray(data) ? data : (data?.items ?? []);

  const handleTrigger = async () => {
    await triggerScan({});
    refetch();
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Scan History</h1>
        <button
          onClick={handleTrigger}
          className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded text-sm"
        >
          Trigger Scan
        </button>
      </div>
      {isLoading ? (
        <p className="text-gray-400">Loading…</p>
      ) : (
        <div className="flex flex-col gap-3">
          {scans.map((s: Record<string, unknown>, i: number) => (
            <div key={String(s.scan_id ?? i)} className="bg-gray-800 rounded-lg p-4">
              <div className="flex justify-between">
                <span className="font-mono text-xs text-gray-400">{String(s.scan_id ?? "")}</span>
                <span className="text-xs text-gray-400">{String(s.scanned_at ?? "")}</span>
              </div>
              <p className="text-sm mt-1">{String(s.repository ?? "")}</p>
            </div>
          ))}
          {scans.length === 0 && <p className="text-gray-500">No scans yet</p>}
        </div>
      )}
    </div>
  );
}
