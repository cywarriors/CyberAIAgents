import { useQuery } from "@tanstack/react-query";
import { getInteractions } from "../api/client";

export default function Interactions() {
  const { data, isLoading } = useQuery({ queryKey: ["interactions"], queryFn: () => getInteractions() });
  const items: any[] = data?.items ?? [];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-2">Interactions</h1>
      <p className="text-gray-400 text-sm mb-6">Total: {data?.total ?? 0}</p>
      {isLoading ? (
        <p>Loading…</p>
      ) : items.length === 0 ? (
        <p className="text-gray-500">No interactions recorded.</p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-800 text-left">
              <th className="px-3 py-2">ID</th>
              <th className="px-3 py-2">Source IP</th>
              <th className="px-3 py-2">Decoy ID</th>
              <th className="px-3 py-2">Action</th>
              <th className="px-3 py-2">Type</th>
            </tr>
          </thead>
          <tbody>
            {items.map((i) => (
              <tr key={i.interaction_id} className="border-b border-gray-800">
                <td className="px-3 py-2 font-mono text-xs">{i.interaction_id}</td>
                <td className="px-3 py-2">{i.source_ip}</td>
                <td className="px-3 py-2 font-mono text-xs">{i.decoy_id}</td>
                <td className="px-3 py-2">{i.action}</td>
                <td className="px-3 py-2">{i.interaction_type ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
