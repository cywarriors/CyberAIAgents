import { useQuery } from "@tanstack/react-query";
import { getDashboard } from "../api/client";

export default function Dashboard() {
  const { data, isLoading } = useQuery({ queryKey: ["dashboard"], queryFn: getDashboard });

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Security Code Review — Dashboard</h1>
      {isLoading ? (
        <p className="text-gray-400">Loading…</p>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: "Total Scans", value: data?.total_scans ?? 0 },
            { label: "SAST Findings", value: data?.sast_count ?? 0 },
            { label: "Secrets Found", value: data?.secrets_count ?? 0 },
            { label: "SCA Vulnerabilities", value: data?.sca_count ?? 0 },
          ].map((m) => (
            <div key={m.label} className="bg-gray-800 rounded-lg p-4">
              <p className="text-gray-400 text-xs mb-1">{m.label}</p>
              <p className="text-2xl font-bold text-indigo-400">{m.value}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
