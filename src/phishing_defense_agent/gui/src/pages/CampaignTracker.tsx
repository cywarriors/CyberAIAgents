import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchCampaigns, getCampaign, type CampaignItem } from "../api/client";
import { ChevronDown, ChevronRight, Target } from "lucide-react";

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-600 text-white",
  medium: "bg-yellow-600 text-black",
  low: "bg-green-600 text-white",
};

const STATUS_BADGE: Record<string, string> = {
  active: "bg-red-600",
  monitoring: "bg-yellow-600 text-black",
  contained: "bg-green-600",
  closed: "bg-gray-600",
};

export default function CampaignTracker() {
  const [severityFilter, setSeverityFilter] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const params = severityFilter ? `severity=${severityFilter}` : undefined;

  const { data, isLoading } = useQuery<CampaignItem[]>({
    queryKey: ["campaigns", severityFilter],
    queryFn: () => fetchCampaigns(params),
    refetchInterval: 30_000,
  });

  const { data: detail } = useQuery<CampaignItem>({
    queryKey: ["campaign", expanded],
    queryFn: () => getCampaign(expanded!),
    enabled: !!expanded,
  });

  const campaigns = data ?? [];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Campaign Tracker</h1>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select
          className="rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {isLoading ? (
        <p className="text-gray-400">Loading…</p>
      ) : campaigns.length === 0 ? (
        <p className="text-gray-500">No phishing campaigns detected.</p>
      ) : (
        <div className="space-y-4">
          {campaigns.map((c) => (
            <div
              key={c.campaign_id}
              className="rounded-xl border border-gray-800 bg-gray-900"
            >
              <button
                className="flex w-full items-center gap-3 p-4 text-left"
                onClick={() =>
                  setExpanded(expanded === c.campaign_id ? null : c.campaign_id)
                }
              >
                {expanded === c.campaign_id ? (
                  <ChevronDown className="h-4 w-4 text-gray-400" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-gray-400" />
                )}
                <Target className="h-5 w-5 text-red-400" />
                <div className="flex-1">
                  <p className="font-semibold">{c.name}</p>
                  <p className="text-xs text-gray-400">
                    {c.email_count} emails · {c.sender_domains.length} domains
                  </p>
                </div>
                <span
                  className={`rounded px-2 py-0.5 text-xs font-bold ${SEVERITY_BADGE[c.severity] ?? "bg-gray-700"}`}
                >
                  {c.severity}
                </span>
                <span
                  className={`rounded px-2 py-0.5 text-xs font-medium ${STATUS_BADGE[c.status] ?? "bg-gray-700"}`}
                >
                  {c.status}
                </span>
              </button>

              {expanded === c.campaign_id && (
                <div className="border-t border-gray-800 px-4 pb-4 pt-3 space-y-3">
                  <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                    <div>
                      <p className="text-xs text-gray-400">First Seen</p>
                      <p className="text-sm">{new Date(c.first_seen).toLocaleString()}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-400">Last Seen</p>
                      <p className="text-sm">{new Date(c.last_seen).toLocaleString()}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-400">Total Emails</p>
                      <p className="text-sm font-bold">{c.email_count}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-400">Status</p>
                      <p className="text-sm font-medium">{c.status}</p>
                    </div>
                  </div>

                  {c.sender_domains.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-400 mb-1">Sender Domains</p>
                      <div className="flex flex-wrap gap-2">
                        {c.sender_domains.map((d) => (
                          <span
                            key={d}
                            className="rounded bg-red-900/50 px-2 py-0.5 text-xs text-red-300"
                          >
                            {d}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {c.target_departments.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-400 mb-1">Target Departments</p>
                      <div className="flex flex-wrap gap-2">
                        {c.target_departments.map((d) => (
                          <span
                            key={d}
                            className="rounded bg-blue-900/50 px-2 py-0.5 text-xs text-blue-300"
                          >
                            {d}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {c.threat_types.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-400 mb-1">Threat Types</p>
                      <div className="flex flex-wrap gap-2">
                        {c.threat_types.map((t) => (
                          <span
                            key={t}
                            className="rounded bg-orange-900/50 px-2 py-0.5 text-xs text-orange-300"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
