import { useQuery } from "@tanstack/react-query";
import { fetchEngagements, type Engagement } from "../api/client";
import { Globe, Server, Wifi } from "lucide-react";

export default function AssetDiscovery() {
  const { data: engagements = [], isLoading } = useQuery({
    queryKey: ["engagements"],
    queryFn: fetchEngagements,
  });

  if (isLoading) return <p className="text-gray-400">Loading assets…</p>;

  // Derive assets from engagement RoE scope
  const assets = engagements.flatMap((e: Engagement) =>
    [
      ...e.roe.scope_ips.map((s, i) => ({
        id: `${e.id}-ip-${i}`,
        engagement: e.name,
        target: s,
        type: s.includes("/") ? "network" : "host",
      })),
      ...e.roe.scope_domains.map((s, i) => ({
        id: `${e.id}-dom-${i}`,
        engagement: e.name,
        target: s,
        type: "domain" as const,
      })),
    ],
  );

  const typeIcon = (t: string) => {
    switch (t) {
      case "network":
        return <Wifi className="h-4 w-4 text-blue-400" />;
      case "domain":
        return <Globe className="h-4 w-4 text-green-400" />;
      default:
        return <Server className="h-4 w-4 text-yellow-400" />;
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Asset Discovery</h1>

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <p className="text-xs uppercase text-gray-500">Total Assets</p>
          <p className="mt-1 text-3xl font-bold text-white">{assets.length}</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <p className="text-xs uppercase text-gray-500">Networks</p>
          <p className="mt-1 text-3xl font-bold text-blue-400">
            {assets.filter((a) => a.type === "network").length}
          </p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <p className="text-xs uppercase text-gray-500">Domains</p>
          <p className="mt-1 text-3xl font-bold text-green-400">
            {assets.filter((a) => a.type === "domain").length}
          </p>
        </div>
      </div>

      <div className="overflow-x-auto rounded-xl border border-gray-800">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800 bg-gray-900 text-xs uppercase text-gray-500">
            <tr>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Target</th>
              <th className="px-4 py-3">Engagement</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800 bg-gray-950">
            {assets.map((a) => (
              <tr key={a.id} className="hover:bg-gray-900">
                <td className="px-4 py-3">{typeIcon(a.type)}</td>
                <td className="px-4 py-3 font-mono text-white">{a.target}</td>
                <td className="px-4 py-3 text-gray-400">{a.engagement}</td>
              </tr>
            ))}
            {assets.length === 0 && (
              <tr>
                <td colSpan={3} className="px-4 py-8 text-center text-gray-500">
                  No assets discovered. Create an engagement with scope targets.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
