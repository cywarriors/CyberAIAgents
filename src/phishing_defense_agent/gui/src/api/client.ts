/** Centralized API client for Phishing Defense Agent BFF. */

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

// Quarantine
export const fetchQuarantineItems = (params?: string) =>
  api.get<QuarantineItem[]>(`/quarantine${params ? `?${params}` : ""}`);
export const getQuarantineItem = (id: string) => api.get<QuarantineItem>(`/quarantine/${id}`);
export const releaseQuarantineItem = (id: string, d: QuarantineReleaseRequest) =>
  api.post<{ message: string }>(`/quarantine/${id}/release`, d);
export const deleteQuarantineItem = (id: string, d: QuarantineDeleteRequest) =>
  api.del<{ message: string }>(`/quarantine/${id}`);

// Verdicts
export const fetchVerdicts = (params?: string) =>
  api.get<VerdictItem[]>(`/verdicts${params ? `?${params}` : ""}`);
export const getVerdict = (id: string) => api.get<VerdictItem>(`/verdicts/${id}`);

// Campaigns
export const fetchCampaigns = (params?: string) =>
  api.get<CampaignItem[]>(`/campaigns${params ? `?${params}` : ""}`);
export const getCampaign = (id: string) => api.get<CampaignItem>(`/campaigns/${id}`);

// Reported emails
export const fetchReportedEmails = (params?: string) =>
  api.get<ReportedEmail[]>(`/reported${params ? `?${params}` : ""}`);
export const reviewReportedEmail = (id: string, d: ReportedEmailReviewRequest) =>
  api.post<{ message: string }>(`/reported/${id}/review`, d);

// Awareness
export const fetchAwarenessMetrics = () => api.get<AwarenessMetrics>("/awareness/metrics");

// Processing
export const processEmails = (d: ProcessEmailsRequest) =>
  api.post<ProcessEmailsResponse>("/process", d);

// Admin
export const fetchAdminHealth = () => api.get<AdminHealth>("/admin/health");
export const fetchAdminConfig = () => api.get<Record<string, unknown>>("/admin/config");
export const fetchAdminStatistics = () => api.get<AdminStatistics>("/admin/statistics");

// ── Types ────────────────────────────────────────────────────────

export interface DashboardSummary {
  total_emails_processed: number;
  emails_blocked: number;
  emails_quarantined: number;
  emails_warned: number;
  emails_allowed: number;
  quarantine_queue_size: number;
  pending_reports: number;
  active_campaigns: number;
  detection_rate: number;
  false_positive_rate: number;
  verdict_breakdown: Record<string, number>;
  threat_type_breakdown: Record<string, number>;
}

export interface QuarantineItem {
  quarantine_id: string;
  email_id: string;
  sender: string;
  recipient: string;
  subject: string;
  received_at: string;
  quarantined_at: string;
  risk_score: number;
  verdict: string;
  threat_types: string[];
  status: string;
}

export interface QuarantineReleaseRequest {
  analyst_id: string;
  reason: string;
}

export interface QuarantineDeleteRequest {
  analyst_id: string;
  reason: string;
}

export interface VerdictItem {
  verdict_id: string;
  email_id: string;
  sender: string;
  recipient: string;
  subject: string;
  timestamp: string;
  risk_score: number;
  verdict: string;
  action: string;
  threat_types: string[];
  explanation: string;
  auth_result: Record<string, unknown>;
  content_signals: Record<string, unknown>[];
  url_analyses: Record<string, unknown>[];
  attachment_analyses: Record<string, unknown>[];
}

export interface CampaignItem {
  campaign_id: string;
  name: string;
  severity: string;
  first_seen: string;
  last_seen: string;
  email_count: number;
  sender_domains: string[];
  target_departments: string[];
  threat_types: string[];
  status: string;
}

export interface ReportedEmail {
  report_id: string;
  reporter_email: string;
  reported_at: string;
  subject: string;
  sender: string;
  processed: boolean;
  verdict: string | null;
  analyst_notes: string | null;
}

export interface ReportedEmailReviewRequest {
  analyst_id: string;
  verdict: string;
  notes: string;
}

export interface AwarenessMetrics {
  total_reports: number;
  true_positive_reports: number;
  false_positive_reports: number;
  report_accuracy_pct: number;
  reports_by_department: Record<string, number>;
  reporting_trend: { date: string; count: number }[];
  top_reporters: { email: string; count: number }[];
  training_completion_pct: number;
  simulation_click_rate: number;
}

export interface ProcessEmailsRequest {
  emails: Record<string, unknown>[];
}

export interface ProcessEmailsResponse {
  processed: number;
  verdicts: VerdictItem[];
}

export interface AdminHealth {
  status: string;
  uptime_seconds: number;
  version: string;
}

export interface AdminStatistics {
  total_processed: number;
  total_blocked: number;
  total_quarantined: number;
  total_warned: number;
  total_allowed: number;
  total_campaigns: number;
  total_reports: number;
  total_iocs: number;
}
