import { useQuery } from "@tanstack/react-query";
import { fetchTuningMetrics } from "../api/client";
import { SlidersHorizontal, ThumbsUp, ThumbsDown, Wrench } from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

export default function TuningWorkbench() {
  const { data, isLoading } = useQuery({
    queryKey: ["tuning"],
    queryFn: fetchTuningMetrics,
  });

  if (isLoading || !data) return <p className="text-gray-400">Loading tuning metrics…</p>;

  const kpis = [
    {
      label: "Total Feedback",
      value: data.total_feedback,
      icon: SlidersHorizontal,
    },
    {
      label: "True Positive Rate",
      value: `${(data.true_positive_rate * 100).toFixed(1)}%`,
      icon: ThumbsUp,
      color: "text-green-400",
    },
    {
      label: "False Positive Rate",
      value: `${(data.false_positive_rate * 100).toFixed(1)}%`,
      icon: ThumbsDown,
      color: "text-red-400",
    },
    {
      label: "Needs Tuning",
      value: data.needs_tuning_count,
      icon: Wrench,
      color: "text-yellow-400",
    },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Tuning Workbench</h1>

      {/* KPI cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {kpis.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-xl border border-gray-800 bg-gray-900 p-5">
            <div className="flex items-center gap-2 text-gray-400">
              <Icon className="h-4 w-4" />
              <span className="text-xs uppercase">{label}</span>
            </div>
            <p className={`mt-2 text-2xl font-bold ${color ?? "text-white"}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Rule hit rates chart */}
      {data.rule_hit_rates.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="mb-4 text-sm font-semibold text-gray-300">Rule Hit Rates</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={data.rule_hit_rates} layout="vertical">
              <XAxis type="number" tick={{ fill: "#9ca3af", fontSize: 12 }} />
              <YAxis
                type="category"
                dataKey="rule_name"
                width={200}
                tick={{ fill: "#9ca3af", fontSize: 11 }}
              />
              <Tooltip />
              <Bar dataKey="hit_count" fill="#6366f1" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recommendations */}
      {data.threshold_recommendations.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="mb-3 font-semibold text-gray-300">Threshold Recommendations</h2>
          <div className="space-y-2">
            {data.threshold_recommendations.map((rec, i) => (
              <div key={i} className="rounded-lg bg-gray-800 px-4 py-3 text-sm text-gray-300">
                {JSON.stringify(rec)}
              </div>
            ))}
          </div>
        </div>
      )}

      {data.total_feedback === 0 && (
        <p className="py-4 text-center text-gray-500">
          No feedback data available yet. Submit feedback on alerts to see tuning insights.
        </p>
      )}
    </div>
  );
}
