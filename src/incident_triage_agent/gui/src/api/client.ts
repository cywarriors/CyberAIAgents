/** Centralized API client for Incident Triage Agent BFF. */

const BASE = "/api/v1";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail ?? `HTTP ${res.status}`);
  }
  return res.json();
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, data?: unknown) =>
    request<T>(path, { method: "POST", body: data ? JSON.stringify(data) : undefined }),
  put: <T>(path: string, data: unknown) =>
    request<T>(path, { method: "PUT", body: JSON.stringify(data) }),
  del: <T>(path: string) => request<T>(path, { method: "DELETE" }),
};

// ── Typed API functions ──────────────────────────────────────────

// Dashboard
export const fetchDashboardSummary = () => api.get<DashboardSummary>("/dashboard/summary");

// Incidents
export const fetchIncidents = (params?: string) =>
  api.get<PaginatedIncidents>(`/incidents${params ? `?${params}` : ""}`);
export const getIncident = (id: string) => api.get<Incident>(`/incidents/${id}`);
export const createIncident = (d: IncidentCreate) => api.post<Incident>("/incidents", d);
export const updateIncident = (id: string, d: IncidentUpdate) =>
  api.put<Incident>(`/incidents/${id}`, d);
export const deleteIncident = (id: string) => api.del<{ message: string }>(`/incidents/${id}`);
export const submitFeedback = (id: string, d: IncidentFeedback) =>
  api.post<{ message: string }>(`/incidents/${id}/feedback`, d);

// Correlations
export const fetchCorrelations = (id: string) =>
  api.get<CorrelationGraph>(`/incidents/${id}/correlations`);

// Playbooks
export const fetchPlaybooks = (id: string) =>
  api.get<PlaybookRecommendation[]>(`/incidents/${id}/playbooks`);

// Analysts
export const fetchAnalystWorkload = () => api.get<AnalystWorkloadItem[]>("/analysts/workload");

// Triage metrics
export const fetchTriageMetrics = () => api.get<TriageMetrics>("/triage/metrics");

// ── Types ────────────────────────────────────────────────────────

export interface DashboardSummary {
  open_incidents: number;
  p1_count: number;
  p2_count: number;
  p3_count: number;
  p4_count: number;
  mttt_seconds: number;
  sla_compliance_pct: number;
  incidents_today: number;
  escalation_rate: number;
  priority_breakdown: Record<string, number>;
  top_categories: { category: string; count: number }[];
}

export interface Incident {
  incident_id: string;
  case_id: string;
  timestamp: string;
  priority: string;
  classification: string;
  severity: string;
  confidence: number;
  triage_summary: string;
  status: string;
  assigned_analyst: string;
  sla_remaining_seconds: number;
  alert_ids: string[];
  entity_profiles: Record<string, unknown>[];
  correlation_groups: Record<string, unknown>[];
  recommended_actions: Record<string, unknown>[];
  timeline: Record<string, unknown>[];
  mitre_technique_ids: string[];
  mitre_tactics: string[];
  evidence: Record<string, unknown>[];
  analyst_notes: string;
}

export interface PaginatedIncidents {
  items: Incident[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface IncidentCreate {
  priority: string;
  classification?: string;
  severity?: string;
  triage_summary?: string;
  alert_ids?: string[];
  mitre_technique_ids?: string[];
  mitre_tactics?: string[];
}

export interface IncidentUpdate {
  status?: string;
  assigned_analyst?: string;
  priority?: string;
  analyst_notes?: string;
}

export interface IncidentFeedback {
  analyst_id: string;
  verdict: string;
  corrected_priority?: string;
  corrected_classification?: string;
  comment?: string;
}

export interface CorrelationNode {
  node_id: string;
  node_type: string;
  label: string;
  severity: string;
}

export interface CorrelationEdge {
  source: string;
  target: string;
  method: string;
}

export interface CorrelationGraph {
  nodes: CorrelationNode[];
  edges: CorrelationEdge[];
}

export interface PlaybookRecommendation {
  playbook_id: string;
  name: string;
  description: string;
  confidence: number;
  steps: string[];
  action_type: string;
}

export interface AnalystWorkloadItem {
  analyst_id: string;
  analyst_name: string;
  open_incidents: number;
  avg_handling_time_seconds: number;
  resolved_today: number;
}

export interface TriageMetrics {
  total_triaged: number;
  mttt_trend: Record<string, unknown>[];
  priority_accuracy: number;
  escalation_rate: number;
  true_positive_rate: number;
  false_positive_rate: number;
  category_distribution: Record<string, number>;
}
