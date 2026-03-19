// API Client for Threat Intelligence Agent BFF

const API_BASE = '/api/v1';

// ============== Type Definitions ==============

export interface IOC {
  id: string;
  type: 'ip' | 'domain' | 'hash_md5' | 'hash_sha1' | 'hash_sha256' | 'url' | 'email';
  value: string;
  confidence_score: number;
  relevance_score: number;
  tlp_level: 'WHITE' | 'GREEN' | 'AMBER' | 'RED';
  status: 'new' | 'active' | 'deprecated' | 'revoked';
  sources: string[];
  first_seen: string;
  last_seen: string;
  associated_actors: string[];
  associated_campaigns: string[];
  tags: string[];
  description?: string;
}

export interface IOCRelationship {
  source_ioc_id: string;
  target_ioc_id: string;
  relationship_type: string;
  confidence: number;
}

export interface IntelBrief {
  id: string;
  title: string;
  level: 'strategic' | 'operational' | 'tactical';
  tlp_level: 'WHITE' | 'GREEN' | 'AMBER' | 'RED';
  executive_summary: string;
  technical_analysis: string;
  attck_techniques: string[];
  recommendations: string[];
  ioc_appendix: string[];
  created_at: string;
  updated_at: string;
  author: string;
  read_count: number;
}

export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  targeted_sectors: string[];
  targeted_regions: string[];
  ttps: ATTCKMapping[];
  associated_campaigns: string[];
  associated_iocs: string[];
  first_seen: string;
  last_seen: string;
  attribution_confidence: number;
}

export interface ATTCKMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  confidence: number;
}

export interface FeedSource {
  id: string;
  name: string;
  source_type: 'osint' | 'commercial' | 'isac' | 'internal';
  url: string;
  enabled: boolean;
  last_poll: string | null;
  last_success: string | null;
  success_rate: number;
  ioc_yield_24h: number;
  quality_score: number;
  false_positive_rate: number;
}

export interface FeedHealth {
  feed_id: string;
  status: 'healthy' | 'degraded' | 'error';
  last_poll: string;
  last_success: string | null;
  poll_count_24h: number;
  error_count_24h: number;
  avg_latency_ms: number;
  ioc_count_24h: number;
}

export interface DashboardMetrics {
  total_iocs: number;
  active_iocs: number;
  iocs_ingested_24h: number;
  iocs_distributed_24h: number;
  briefs_published_7d: number;
  active_actors: number;
  active_campaigns: number;
  avg_confidence_score: number;
  feeds_healthy: number;
  feeds_total: number;
  operationalization_rate: number;
  dedup_ratio: number;
  ioc_type_distribution: Record<string, number>;
  ioc_ingestion_timeline: { timestamp: string; count: number }[];
  top_threat_actors: { name: string; ioc_count: number }[];
  top_campaigns: { name: string; ioc_count: number }[];
}

export interface Campaign {
  id: string;
  name: string;
  description: string;
  threat_actor: string;
  start_date: string;
  end_date: string | null;
  status: 'active' | 'inactive';
  targeted_sectors: string[];
  targeted_regions: string[];
  ttps: ATTCKMapping[];
  associated_iocs: string[];
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface AdminHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  uptime_seconds: number;
  version: string;
  components: { name: string; status: string; latency_ms: number }[];
}

export interface AdminStats {
  total_iocs_processed: number;
  total_briefs_generated: number;
  total_iocs_distributed: number;
  pipeline_runs_24h: number;
  avg_pipeline_duration_ms: number;
  error_rate_24h: number;
}

// ============== API Functions ==============

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`API error ${response.status}: ${error}`);
  }
  return response.json();
}

// Dashboard
export async function fetchDashboardMetrics(): Promise<DashboardMetrics> {
  return fetchJson<DashboardMetrics>(`${API_BASE}/dashboard/intel`);
}

// IOCs
export async function fetchIOCs(params?: {
  page?: number;
  page_size?: number;
  type?: string;
  status?: string;
  confidence_min?: number;
  source?: string;
  search?: string;
}): Promise<PaginatedResponse<IOC>> {
  const searchParams = new URLSearchParams();
  if (params?.page) searchParams.set('page', String(params.page));
  if (params?.page_size) searchParams.set('page_size', String(params.page_size));
  if (params?.type) searchParams.set('type', params.type);
  if (params?.status) searchParams.set('status', params.status);
  if (params?.confidence_min) searchParams.set('confidence_min', String(params.confidence_min));
  if (params?.source) searchParams.set('source', params.source);
  if (params?.search) searchParams.set('search', params.search);
  return fetchJson<PaginatedResponse<IOC>>(`${API_BASE}/iocs?${searchParams}`);
}

export async function fetchIOCById(id: string): Promise<IOC> {
  return fetchJson<IOC>(`${API_BASE}/iocs/${id}`);
}

export async function updateIOC(id: string, data: Partial<IOC>): Promise<IOC> {
  return fetchJson<IOC>(`${API_BASE}/iocs/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function fetchIOCRelationships(id: string): Promise<IOCRelationship[]> {
  return fetchJson<IOCRelationship[]>(`${API_BASE}/iocs/${id}/relationships`);
}

export async function exportIOCs(params: {
  format: 'stix' | 'csv';
  ioc_ids?: string[];
  filters?: Record<string, string>;
}): Promise<Blob> {
  const response = await fetch(`${API_BASE}/iocs/export`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!response.ok) {
    throw new Error(`Export failed: ${response.status}`);
  }
  return response.blob();
}

// Briefs
export async function fetchBriefs(params?: {
  page?: number;
  page_size?: number;
  level?: string;
}): Promise<PaginatedResponse<IntelBrief>> {
  const searchParams = new URLSearchParams();
  if (params?.page) searchParams.set('page', String(params.page));
  if (params?.page_size) searchParams.set('page_size', String(params.page_size));
  if (params?.level) searchParams.set('level', params.level);
  return fetchJson<PaginatedResponse<IntelBrief>>(`${API_BASE}/briefs?${searchParams}`);
}

export async function fetchBriefById(id: string): Promise<IntelBrief> {
  return fetchJson<IntelBrief>(`${API_BASE}/briefs/${id}`);
}

// Actors
export async function fetchActors(params?: {
  page?: number;
  page_size?: number;
  search?: string;
}): Promise<PaginatedResponse<ThreatActor>> {
  const searchParams = new URLSearchParams();
  if (params?.page) searchParams.set('page', String(params.page));
  if (params?.page_size) searchParams.set('page_size', String(params.page_size));
  if (params?.search) searchParams.set('search', params.search);
  return fetchJson<PaginatedResponse<ThreatActor>>(`${API_BASE}/actors?${searchParams}`);
}

export async function fetchActorById(id: string): Promise<ThreatActor> {
  return fetchJson<ThreatActor>(`${API_BASE}/actors/${id}`);
}

// Feeds
export async function fetchFeeds(): Promise<FeedSource[]> {
  return fetchJson<FeedSource[]>(`${API_BASE}/feeds`);
}

export async function fetchFeedById(id: string): Promise<FeedSource> {
  return fetchJson<FeedSource>(`${API_BASE}/feeds/${id}`);
}

export async function createFeed(data: Omit<FeedSource, 'id' | 'last_poll' | 'last_success' | 'success_rate' | 'ioc_yield_24h' | 'quality_score' | 'false_positive_rate'>): Promise<FeedSource> {
  return fetchJson<FeedSource>(`${API_BASE}/feeds`, {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function updateFeed(id: string, data: Partial<FeedSource>): Promise<FeedSource> {
  return fetchJson<FeedSource>(`${API_BASE}/feeds/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteFeed(id: string): Promise<void> {
  await fetch(`${API_BASE}/feeds/${id}`, { method: 'DELETE' });
}

export async function fetchFeedHealth(id: string): Promise<FeedHealth> {
  return fetchJson<FeedHealth>(`${API_BASE}/feeds/${id}/health`);
}

// Campaigns
export async function fetchCampaigns(params?: {
  page?: number;
  page_size?: number;
  status?: string;
}): Promise<PaginatedResponse<Campaign>> {
  const searchParams = new URLSearchParams();
  if (params?.page) searchParams.set('page', String(params.page));
  if (params?.page_size) searchParams.set('page_size', String(params.page_size));
  if (params?.status) searchParams.set('status', params.status);
  return fetchJson<PaginatedResponse<Campaign>>(`${API_BASE}/campaigns?${searchParams}`);
}

// Processing
export async function triggerPipeline(data?: { intel_records?: unknown[] }): Promise<{ run_id: string; status: string }> {
  return fetchJson<{ run_id: string; status: string }>(`${API_BASE}/process`, {
    method: 'POST',
    body: JSON.stringify(data || {}),
  });
}

// Admin
export async function fetchAdminHealth(): Promise<AdminHealth> {
  return fetchJson<AdminHealth>('/admin/health');
}

export async function fetchAdminConfig(): Promise<Record<string, unknown>> {
  return fetchJson<Record<string, unknown>>('/admin/config');
}

export async function fetchAdminStats(): Promise<AdminStats> {
  return fetchJson<AdminStats>('/admin/statistics');
}

export async function fetchAuditLog(params?: {
  page?: number;
  page_size?: number;
}): Promise<PaginatedResponse<{ timestamp: string; action: string; user: string; details: string }>> {
  const searchParams = new URLSearchParams();
  if (params?.page) searchParams.set('page', String(params.page));
  if (params?.page_size) searchParams.set('page_size', String(params.page_size));
  return fetchJson(`/admin/audit-log?${searchParams}`);
}

// WebSocket connection for real-time notifications
export function connectNotifications(
  onMessage: (data: { type: string; payload: unknown }) => void,
  onError?: (error: Event) => void
): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${protocol}//${window.location.host}/ws/notifications`);
  
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onMessage(data);
    } catch (e) {
      console.error('Failed to parse WebSocket message:', e);
    }
  };
  
  ws.onerror = (error) => {
    console.error('WebSocket error:', error);
    onError?.(error);
  };
  
  return ws;
}
