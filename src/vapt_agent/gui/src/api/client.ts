/** Centralized API client with TanStack Query hooks. */

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

// ── Generic helpers ──────────────────────────────────────────────
export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, data: unknown) =>
    request<T>(path, { method: "POST", body: JSON.stringify(data) }),
  put: <T>(path: string, data: unknown) =>
    request<T>(path, { method: "PUT", body: JSON.stringify(data) }),
  del: <T>(path: string) => request<T>(path, { method: "DELETE" }),
};

// ── Typed API functions ──────────────────────────────────────────
// Dashboard
export const fetchDashboard = () => api.get<DashboardSummary>("/dashboard/summary");

// Engagements
export const fetchEngagements = () => api.get<Engagement[]>("/engagements");
export const createEngagement = (d: EngagementCreate) =>
  api.post<Engagement>("/engagements", d);
export const updateEngagement = (id: string, d: Partial<EngagementCreate>) =>
  api.put<Engagement>(`/engagements/${id}`, d);
export const deleteEngagement = (id: string) =>
  api.del<{ message: string }>(`/engagements/${id}`);

// Findings
export const fetchFindings = (params?: string) =>
  api.get<PaginatedFindings>(`/findings${params ? `?${params}` : ""}`);

// Scans
export const fetchScans = () => api.get<Scan[]>("/scans");
export const createScan = (d: ScanCreate) => api.post<Scan>("/scans", d);
export const abortScan = (id: string) => api.post<{ message: string }>(`/scans/${id}/abort`, {});

// Attack paths
export const fetchAttackPaths = (engagementId?: string) =>
  api.get<AttackPath[]>(`/attack-paths${engagementId ? `?engagement_id=${engagementId}` : ""}`);

// Exploits
export const fetchExploits = () => api.get<ExploitModule[]>("/exploits");
export const executeExploit = (moduleId: string, d: ExploitExecReq) =>
  api.post<ExploitExecRes>(`/exploits/${moduleId}/execute`, d);

// Reports
export const fetchReports = (engagementId?: string) =>
  api.get<Report[]>(`/reports${engagementId ? `?engagement_id=${engagementId}` : ""}`);
export const createReport = (d: ReportCreate) => api.post<Report>("/reports", d);
export const deleteReport = (id: string) => api.del<{ message: string }>(`/reports/${id}`);

// Compliance
export const fetchSchedules = () => api.get<ComplianceSchedule[]>("/compliance/schedules");
export const createSchedule = (d: ScheduleCreate) =>
  api.post<ComplianceSchedule>("/compliance/schedules", d);
export const deleteSchedule = (id: string) =>
  api.del<{ message: string }>(`/compliance/schedules/${id}`);

// Admin
export const fetchHealth = () => api.get<SystemHealth>("/admin/health");

// ── Types ────────────────────────────────────────────────────────
export interface DashboardSummary {
  active_engagements: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  assets_discovered: number;
  attack_paths_found: number;
  exploits_validated: number;
  reports_generated: number;
  severity_breakdown: Record<string, number>;
  risk_trend: Record<string, unknown>[];
  top_vulnerable_assets: Record<string, unknown>[];
}

export interface RoEPayload {
  scope_ips: string[];
  scope_domains: string[];
  scope_cloud_accounts: string[];
  exclusions: string[];
  allow_destructive: boolean;
  start_time: string | null;
  end_time: string | null;
}

export interface Engagement {
  id: string;
  name: string;
  description: string;
  status: string;
  roe: RoEPayload;
  created_at: string;
  updated_at: string;
  findings_count: number;
  critical_count: number;
  high_count: number;
}

export interface EngagementCreate {
  name: string;
  description?: string;
  roe: RoEPayload;
  scheduled_start?: string;
}

export interface Finding {
  id: string;
  engagement_id: string;
  asset_id: string;
  title: string;
  severity: string;
  cve_id: string | null;
  cwe_id: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  composite_score: number;
  in_kev: boolean;
  status: string;
  matched_rules: string[];
  remediation: string;
  evidence: Record<string, unknown>;
}

export interface PaginatedFindings {
  items: Finding[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface Scan {
  id: string;
  engagement_id: string;
  status: string;
  progress: number;
  targets: string[];
  engines: string[];
  findings_count: number;
  started_at: string | null;
  completed_at: string | null;
}

export interface ScanCreate {
  engagement_id: string;
  targets: string[];
  engines?: string[];
}

export interface AttackPath {
  id: string;
  engagement_id: string;
  steps: AttackPathStep[];
  composite_risk: number;
  asset_count: number;
}

export interface AttackPathStep {
  step: number;
  asset_id: string;
  technique: string;
  mitre_technique_id: string | null;
}

export interface ExploitModule {
  id: string;
  name: string;
  description: string;
  risk_level: string;
  cve_id: string | null;
  mitre_technique_id: string | null;
}

export interface ExploitExecReq {
  target_asset_id: string;
  finding_id: string;
  approval_token?: string;
}

export interface ExploitExecRes {
  execution_id: string;
  module_id: string;
  target_asset_id: string;
  finding_id: string;
  status: string;
  success: boolean | null;
  rollback_success: boolean | null;
  started_at: string | null;
}

export interface Report {
  id: string;
  engagement_id: string;
  report_type: string;
  status: string;
  generated_at: string | null;
  download_url: string | null;
  content: Record<string, unknown> | null;
}

export interface ReportCreate {
  engagement_id: string;
  report_type?: string;
  sections?: string[];
  include_findings?: boolean;
}

export interface ComplianceSchedule {
  id: string;
  engagement_id: string;
  framework: string;
  frequency: string;
  next_due: string | null;
  last_completed: string | null;
  status: string;
}

export interface ScheduleCreate {
  engagement_id: string;
  framework: string;
  frequency?: string;
  next_due?: string;
}

export interface SystemHealth {
  status: string;
  uptime_seconds: number;
  scanner_engines: Record<string, string>;
  kafka_connected: boolean;
  redis_connected: boolean;
  postgres_connected: boolean;
}
