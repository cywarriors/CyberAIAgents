import { useQuery } from "@tanstack/react-query";
import { getProfiles } from "../api/client";

const THREAT_COLOR: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-300",
  low: "text-green-400",
};

export default function AttackerProfiles() {
  const { data, isLoading } = useQuery({ queryKey: ["profiles"], queryFn: getProfiles });
  const items: any[] = data?.items ?? [];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Attacker Profiles</h1>
      {isLoading ? (
        <p>Loading…</p>
      ) : items.length === 0 ? (
        <p className="text-gray-500">No attacker profiles yet.</p>
      ) : (
        <div className="space-y-4">
          {items.map((p) => (
            <div key={p.source_ip} className="bg-gray-800 rounded p-4">
              <div className="flex justify-between mb-2">
                <span className="font-mono font-bold">{p.source_ip}</span>
                <span className={`text-sm font-bold uppercase ${THREAT_COLOR[p.threat_level] ?? ""}`}>
                  {p.threat_level}
                </span>
              </div>
              <div className="grid grid-cols-3 gap-4 text-sm">
                <div>
                  <span className="text-gray-400">Interactions</span>
                  <div className="font-bold">{p.interaction_count ?? 0}</div>
                </div>
                <div>
                  <span className="text-gray-400">Dominant Behaviour</span>
                  <div className="font-bold">{p.dominant_behavior ?? "-"}</div>
                </div>
                <div>
                  <span className="text-gray-400">Decoys Touched</span>
                  <div className="font-bold">{(p.decoys_touched ?? []).length}</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
