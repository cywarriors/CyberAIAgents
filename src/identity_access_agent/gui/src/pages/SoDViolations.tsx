import { useQuery } from "@tanstack/react-query";
import { fetchSoDViolations, type SoDViolationItem } from "../api/client";

export default function SoDViolations() {
  const { data, isLoading } = useQuery<SoDViolationItem[]>({
    queryKey: ["sodViolations"],
    queryFn: () => fetchSoDViolations(),
    refetchInterval: 15_000,
  });

  if (isLoading) return <p className="text-gray-400">Loading SoD violations…</p>;

  const items = data ?? [];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Segregation of Duties Violations</h1>
      {items.length === 0 ? (
        <p className="text-gray-500">No SoD violations detected.</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-900">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-gray-400">
                <th className="p-3">User</th>
                <th className="p-3">Conflicting Roles</th>
                <th className="p-3">Rule</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Recommendation</th>
              </tr>
            </thead>
            <tbody>
              {items.map((v, i) => (
                <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="p-3 font-medium">{v.username || v.user_id}</td>
                  <td className="p-3 text-gray-400">{v.conflicting_roles.join(", ")}</td>
                  <td className="p-3">{v.rule_name || v.rule_id}</td>
                  <td className="p-3">
                    <span className="rounded px-2 py-0.5 text-xs font-semibold text-orange-400 bg-orange-900/30">
                      {v.severity}
                    </span>
                  </td>
                  <td className="p-3 max-w-xs truncate text-gray-400">{v.recommendation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
