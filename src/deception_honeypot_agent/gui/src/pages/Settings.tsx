import { useQuery } from "@tanstack/react-query";
import axios from "axios";

const getConfig = () => axios.get("/admin/config").then((r) => r.data);

export default function Settings() {
  const { data, isLoading } = useQuery({ queryKey: ["config"], queryFn: getConfig });

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Settings</h1>
      <div className="bg-gray-800 rounded p-6 max-w-lg">
        <h2 className="font-semibold mb-4">Agent Configuration</h2>
        {isLoading ? (
          <p>Loading…</p>
        ) : (
          <dl className="space-y-3 text-sm">
            {data &&
              Object.entries(data).map(([k, v]) => (
                <div key={k} className="flex justify-between">
                  <dt className="text-gray-400">{k.replace(/_/g, " ")}</dt>
                  <dd className="font-mono">{String(v)}</dd>
                </div>
              ))}
          </dl>
        )}
      </div>
    </div>
  );
}
