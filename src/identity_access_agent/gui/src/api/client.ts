/** Centralized API client for Identity & Access Monitoring Agent BFF. */

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

// Risk Scores
export const fetchRiskScores = (params?: string) =>
  api.get<RiskScoreItem[]>(`/risk-scores${params ? `?${params}` : ""}`);
export const getUserRiskScore = (userId: string) =>
  api.get<RiskScoreItem>(`/risk-scores/${userId}`);

// Alerts
export const fetchAlerts = (params?: string) =>
  api.get<AlertItem[]>(`/alerts${params ? `?${params}` : ""}`);
export const getAlert = (id: string) => api.get<AlertItem>(`/alerts/${id}`);
export const submitAlertFeedback = (id: string, d: FeedbackRequest) =>
  api.post<{ message: string }>(`/alerts/${id}/feedback`, d);
export const closeAlert = (id: string) =>
  api.post<{ message: string }>(`/alerts/${id}/close`);

// Users
export const fetchUsers = (params?: string) =>
  api.get<UserRiskItem[]>(`/users${params ? `?${params}` : ""}`);
export const getUser = (userId: string) => api.get<UserRiskItem>(`/users/${userId}`);

// SoD Violations
export const fetchSoDViolations = (params?: string) =>
  api.get<SoDViolationItem[]>(`/sod-violations${params ? `?${params}` : ""}`);

// Recommendations
export const fetchRecommendations = (params?: string) =>
  api.get<RecommendationItem[]>(`/recommendations${params ? `?${params}` : ""}`);

// Processing
export const processEvents = (d: ProcessEventsRequest) =>
  api.post<ProcessEventsResponse>("/process", d);

// Admin
export const fetchAdminHealth = () => api.get<AdminHealth>("/admin/health");
export const fetchAdminConfig = () => api.get<Record<string, unknown>>("/admin/config");
export const fetchAdminStatistics = () => api.get<AdminStatistics>("/admin/statistics");
export const fetchAuditLog = () => api.get<FeedbackEntry[]>("/admin/audit-log");

// ── Types ────────────────────────────────────────────────────────

export interface DashboardSummary {
  total_events_processed: number;
  critical_risk_users: number;
  high_risk_users: number;
  medium_risk_users: number;
  low_risk_users: number;
  total_alerts: number;
  open_alerts: number;
  sod_violations: number;
  impossible_travel_detections: number;
  mfa_fatigue_detections: number;
  brute_force_detections: number;
  privilege_escalation_detections: number;
  false_positive_rate: number;
  mean_risk_score: number;
  top_risky_users: { user_id: string; username: string; risk_score: number }[];
  risk_trend: { date: string; score: number }[];
}

export interface RiskScoreItem {
  user_id: string;
  username: string;
  risk_score: number;
  risk_level: string;
  indicators: { indicator_type: string; description: string; severity: string }[];
  components: Record<string, number>;
  explanation: string;
  recommended_control: string;
  confidence: number;
  timestamp: string;
}

export interface AlertItem {
  alert_id: string;
  user_id: string;
  username: string;
  severity: string;
  title: string;
  description: string;
  risk_score: number;
  indicators: { indicator_type: string; description: string }[];
  recommended_control: string;
  status: string;
  created_at: string;
  ticket_id: string;
}

export interface UserRiskItem {
  user_id: string;
  username: string;
  department: string;
  risk_score: number;
  risk_level: string;
  active_alerts: number;
  sod_violations: number;
  last_login: string;
  is_vip: boolean;
}

export interface SoDViolationItem {
  user_id: string;
  username: string;
  conflicting_roles: string[];
  conflicting_permissions: string[];
  rule_id: string;
  rule_name: string;
  severity: string;
  recommendation: string;
}

export interface RecommendationItem {
  user_id: string;
  username: string;
  control: string;
  reason: string;
  risk_score: number;
  risk_level: string;
  auto_enforce: boolean;
  requires_approval: boolean;
  timestamp: string;
}

export interface FeedbackRequest {
  analyst_id: string;
  verdict: string;
  notes: string;
}

export interface ProcessEventsRequest {
  auth_events: Record<string, unknown>[];
  role_changes: Record<string, unknown>[];
}

export interface ProcessEventsResponse {
  message: string;
  auth_events_processed: number;
  role_changes_processed: number;
  risk_scores_computed: number;
  alerts_created: number;
  sod_violations: number;
  recommendations: number;
}

export interface AdminHealth {
  status: string;
  uptime_seconds: number;
  risk_scores_in_store: number;
  alerts_in_store: number;
  users_tracked: number;
  sod_violations: number;
}

export interface AdminStatistics {
  total_risk_scores: number;
  risk_level_distribution: Record<string, number>;
  total_alerts: number;
  alert_severity_distribution: Record<string, number>;
  sod_violations: number;
  users_tracked: number;
  feedback_count: number;
}

export interface FeedbackEntry {
  alert_id: string;
  analyst_id: string;
  verdict: string;
  notes: string;
  timestamp: string;
}
