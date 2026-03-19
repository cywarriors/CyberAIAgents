import { useQuery } from "@tanstack/react-query";
import { getDecoys } from "../api/client";

export default function Decoys() {
  const { data, isLoading } = useQuery({ queryKey: ["decoys"], queryFn: getDecoys });
  const items: any[] = data?.items ?? [];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Decoy Inventory</h1>
      {isLoading ? (
        <p>Loading…</p>
      ) : items.length === 0 ? (
        <p className="text-gray-500">No decoys deployed.</p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-800 text-left">
              <th className="px-3 py-2">ID</th>
              <th className="px-3 py-2">Type</th>
              <th className="px-3 py-2">Service</th>
              <th className="px-3 py-2">Address</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Interactions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((d) => (
              <tr key={d.decoy_id} className="border-b border-gray-800">
                <td className="px-3 py-2 font-mono text-xs">{d.decoy_id}</td>
                <td className="px-3 py-2">{d.decoy_type}</td>
                <td className="px-3 py-2">{d.service}</td>
                <td className="px-3 py-2">{d.address ?? "-"}</td>
                <td className="px-3 py-2">
                  <span className={d.status === "active" ? "text-green-400" : "text-gray-500"}>{d.status}</span>
                </td>
                <td className="px-3 py-2">{d.interaction_count ?? 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
