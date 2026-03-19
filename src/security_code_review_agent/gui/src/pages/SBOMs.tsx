import { useQuery } from "@tanstack/react-query";
import { getSBOMs } from "../api/client";

export default function SBOMs() {
  const { data, isLoading } = useQuery({ queryKey: ["sboms"], queryFn: getSBOMs });
  const items = Array.isArray(data) ? data : (data?.items ?? []);

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Software Bill of Materials</h1>
      {isLoading ? (
        <p className="text-gray-400">Loading…</p>
      ) : (
        <div className="flex flex-col gap-3">
          {items.map((s: Record<string, unknown>, i: number) => (
            <div key={String(s.sbom_id ?? i)} className="bg-gray-800 rounded-lg p-4">
              <div className="flex justify-between mb-2">
                <span className="font-semibold">{String(s.repository ?? "")}</span>
                <span className="text-xs text-gray-400">{String(s.format ?? "CycloneDX")}</span>
              </div>
              <p className="text-xs text-gray-400">
                Components: {String(s.component_count ?? 0)} · Generated: {String(s.generated_at ?? "")}
              </p>
            </div>
          ))}
          {items.length === 0 && <p className="text-gray-500">No SBOMs generated yet</p>}
        </div>
      )}
    </div>
  );
}
