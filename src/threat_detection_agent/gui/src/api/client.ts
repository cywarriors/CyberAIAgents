/** Centralized API client for Threat Detection Agent BFF. */

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
export const fetchDashboardMetrics = () => api.get<DashboardMetrics>("/dashboard/metrics");

// Alerts
export const fetchAlerts = (params?: string) =>
  api.get<PaginatedAlerts>(`/alerts${params ? `?${params}` : ""}`);
export const getAlert = (id: string) => api.get<Alert>(`/alerts/${id}`);
export const updateAlert = (id: string, d: Partial<Alert>) =>
  api.put<Alert>(`/alerts/${id}`, d);
export const submitFeedback = (id: string, d: AlertFeedback) =>
  api.post<{ message: string }>(`/alerts/${id}/feedback`, d);

// Rules
export const fetchRules = (status?: string) =>
  api.get<Rule[]>(`/rules${status ? `?status=${status}` : ""}`);
export const createRule = (d: RuleCreate) => api.post<Rule>("/rules", d);
export const updateRule = (id: string, d: Partial<RuleCreate>) =>
  api.put<Rule>(`/rules/${id}`, d);
export const deleteRule = (id: string) => api.del<{ message: string }>(`/rules/${id}`);
export const testRule = (id: string, d: { test_events: Record<string, unknown>[] }) =>
  api.post<RuleTestResult>(`/rules/${id}/test`, d);

// Anomalies
export const fetchAnomalies = (params?: string) =>
  api.get<Anomaly[]>(`/anomalies${params ? `?${params}` : ""}`);

// Coverage
export const fetchCoverage = () => api.get<CoverageData>("/coverage/attack");

// Pipeline
export const fetchPipelineHealth = () => api.get<PipelineHealth>("/pipeline/health");

// Tuning
export const fetchTuningMetrics = () => api.get<TuningMetrics>("/tuning/metrics");

// ── Types ────────────────────────────────────────────────────────

export interface DashboardMetrics {
  total_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  medium_alerts: number;
  low_alerts: number;
  info_alerts: number;
  active_anomalies: number;
  rules_deployed: number;
  mttd_seconds: number;
  pipeline_throughput_eps: number;
  severity_breakdown: Record<string, number>;
  top_triggered_rules: { rule_id: string; rule_name: string; hit_count: number }[];
  alert_volume_timeline: Record<string, unknown>[];
}

export interface Alert {
  alert_id: string;
  timestamp: string;
  severity: string;
  confidence: number;
  mitre_technique_ids: string[];
  mitre_tactics: string[];
  source_type: string;
  entity_ids: string[];
  matched_event_ids: string[];
  evidence: Record<string, unknown>[];
  description: string;
  status: string;
  analyst_notes: string;
  related_alert_ids: string[];
}

export interface PaginatedAlerts {
  items: Alert[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface AlertFeedback {
  analyst_id: string;
  verdict: string;
  comment?: string;
}

export interface Rule {
  rule_id: string;
  rule_name: string;
  mitre_technique_id: string;
  mitre_tactic: string;
  severity: string;
  description: string;
  logic: string;
  status: string;
  created_at: string;
  updated_at: string;
  hit_count: number;
}

export interface RuleCreate {
  rule_name: string;
  mitre_technique_id?: string;
  mitre_tactic?: string;
  severity?: string;
  description?: string;
  logic?: string;
}

export interface RuleTestResult {
  rule_id: string;
  events_tested: number;
  matches_found: number;
  matched_event_ids: string[];
}

export interface Anomaly {
  anomaly_id: string;
  timestamp: string;
  anomaly_type: string;
  anomaly_score: number;
  baseline_value: number;
  observed_value: number;
  entity_type: string;
  entity_id: string;
  description: string;
}

export interface TechniqueCoverage {
  technique_id: string;
  technique_name: string;
  tactic: string;
  rule_count: number;
  alert_count: number;
  covered: boolean;
}

export interface CoverageData {
  total_techniques: number;
  covered_techniques: number;
  coverage_percentage: number;
  techniques: TechniqueCoverage[];
}

export interface NodeHealth {
  node_name: string;
  status: string;
  events_processed: number;
  errors: number;
  avg_latency_ms: number;
  last_heartbeat: string;
}

export interface PipelineHealth {
  status: string;
  uptime_seconds: number;
  nodes: NodeHealth[];
  kafka_connected: boolean;
  redis_connected: boolean;
  postgres_connected: boolean;
  queue_depth: number;
}

export interface TuningMetrics {
  total_feedback: number;
  true_positive_rate: number;
  false_positive_rate: number;
  needs_tuning_count: number;
  rule_hit_rates: { rule_id: string; rule_name: string; hit_count: number; status: string }[];
  threshold_recommendations: Record<string, unknown>[];
}
