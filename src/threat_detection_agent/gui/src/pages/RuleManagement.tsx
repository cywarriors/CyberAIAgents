import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchRules, createRule, updateRule, deleteRule, type Rule } from "../api/client";
import { Plus, Trash2, Edit, CheckCircle } from "lucide-react";

const STATUS_BADGE: Record<string, string> = {
  draft: "bg-gray-700 text-gray-300",
  testing: "bg-yellow-900 text-yellow-300",
  production: "bg-green-900 text-green-300",
  deprecated: "bg-red-900 text-red-300",
};

export default function RuleManagement() {
  const qc = useQueryClient();
  const { data: rules = [], isLoading } = useQuery({
    queryKey: ["rules"],
    queryFn: () => fetchRules(),
  });

  const createMut = useMutation({
    mutationFn: createRule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });
  const updateMut = useMutation({
    mutationFn: ({ id, d }: { id: string; d: Partial<Rule> }) => updateRule(id, d),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });
  const deleteMut = useMutation({
    mutationFn: deleteRule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });

  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [technique, setTechnique] = useState("");
  const [tactic, setTactic] = useState("");
  const [severity, setSeverity] = useState("Medium");
  const [description, setDescription] = useState("");
  const [logic, setLogic] = useState("");

  function handleCreate() {
    createMut.mutate({
      rule_name: name,
      mitre_technique_id: technique,
      mitre_tactic: tactic,
      severity,
      description,
      logic,
    });
    setShowForm(false);
    setName("");
    setTechnique("");
    setTactic("");
    setDescription("");
    setLogic("");
  }

  if (isLoading) return <p className="text-gray-400">Loading rules…</p>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Rule Management</h1>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
        >
          <Plus className="h-4 w-4" /> New Rule
        </button>
      </div>

      {showForm && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5 space-y-3">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Rule name"
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-brand-500 focus:outline-none"
          />
          <div className="grid grid-cols-3 gap-3">
            <input
              value={technique}
              onChange={(e) => setTechnique(e.target.value)}
              placeholder="MITRE Technique ID"
              className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none"
            />
            <input
              value={tactic}
              onChange={(e) => setTactic(e.target.value)}
              placeholder="MITRE Tactic"
              className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none"
            />
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:outline-none"
            >
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
              <option value="Info">Info</option>
            </select>
          </div>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Description"
            rows={2}
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none"
          />
          <textarea
            value={logic}
            onChange={(e) => setLogic(e.target.value)}
            placeholder="Rule logic (Sigma / YARA / custom)"
            rows={4}
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 font-mono text-sm text-white placeholder-gray-500 focus:outline-none"
          />
          <button
            onClick={handleCreate}
            disabled={!name || createMut.isPending}
            className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
          >
            Create Rule
          </button>
        </div>
      )}

      {/* Rules table */}
      <div className="overflow-x-auto rounded-xl border border-gray-800">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-gray-800 bg-gray-900 text-xs uppercase text-gray-400">
            <tr>
              <th className="px-4 py-3">Rule</th>
              <th className="px-4 py-3">Technique</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Hits</th>
              <th className="px-4 py-3">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800 bg-gray-950">
            {rules.map((r: Rule) => (
              <tr key={r.rule_id} className="hover:bg-gray-900">
                <td className="px-4 py-3">
                  <p className="font-medium text-white">{r.rule_name}</p>
                  <p className="text-xs text-gray-500">{r.rule_id}</p>
                </td>
                <td className="px-4 py-3 text-gray-300">{r.mitre_technique_id || "—"}</td>
                <td className="px-4 py-3 text-gray-300">{r.severity}</td>
                <td className="px-4 py-3">
                  <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_BADGE[r.status] ?? STATUS_BADGE.draft}`}>
                    {r.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-gray-300">{r.hit_count}</td>
                <td className="px-4 py-3">
                  <div className="flex gap-1">
                    {r.status === "draft" && (
                      <button
                        onClick={() => updateMut.mutate({ id: r.rule_id, d: { status: "testing" } })}
                        title="Move to Testing"
                        className="rounded p-1.5 text-gray-400 hover:bg-yellow-900 hover:text-yellow-300"
                      >
                        <Edit className="h-3.5 w-3.5" />
                      </button>
                    )}
                    {r.status === "testing" && (
                      <button
                        onClick={() => updateMut.mutate({ id: r.rule_id, d: { status: "production" } })}
                        title="Deploy to Production"
                        className="rounded p-1.5 text-gray-400 hover:bg-green-900 hover:text-green-300"
                      >
                        <CheckCircle className="h-3.5 w-3.5" />
                      </button>
                    )}
                    <button
                      onClick={() => deleteMut.mutate(r.rule_id)}
                      className="rounded p-1.5 text-gray-400 hover:bg-red-900 hover:text-red-300"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rules.length === 0 && (
          <p className="py-8 text-center text-gray-500">No rules configured.</p>
        )}
      </div>
    </div>
  );
}
