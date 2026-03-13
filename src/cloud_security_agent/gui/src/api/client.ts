import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8006'

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: { 'Content-Type': 'application/json' },
})

export const cspmApi = {
  // Dashboard
  getPostureDashboard: () => apiClient.get('/api/v1/dashboard/posture'),
  getComplianceTrend: () => apiClient.get('/api/v1/dashboard/compliance-trend'),
  getFindingsByService: () => apiClient.get('/api/v1/dashboard/findings-by-service'),
  getProviderSummary: () => apiClient.get('/api/v1/dashboard/provider-summary'),

  // Findings
  listFindings: (params?: Record<string, string | number>) =>
    apiClient.get('/api/v1/findings', { params }),
  getFindingDetail: (id: string) => apiClient.get(`/api/v1/findings/${encodeURIComponent(id)}`),
  updateFindingStatus: (id: string, status: string) =>
    apiClient.put(`/api/v1/findings/${encodeURIComponent(id)}/status`, { new_status: status }),

  // Accounts
  listAccounts: () => apiClient.get('/api/v1/accounts'),
  getAccountResources: (accountId: string, params?: Record<string, string | number>) =>
    apiClient.get(`/api/v1/accounts/${encodeURIComponent(accountId)}/resources`, { params }),

  // Compliance
  getComplianceScores: (params?: Record<string, string>) =>
    apiClient.get('/api/v1/compliance/scores', { params }),
  getComplianceControls: (params?: Record<string, string>) =>
    apiClient.get('/api/v1/compliance/controls', { params }),

  // IaC
  listIaCScans: (params?: Record<string, string | number>) =>
    apiClient.get('/api/v1/iac/scans', { params }),
  triggerIaCScan: (data: { template_content: string; template_path: string; framework: string; repository?: string; branch?: string }) =>
    apiClient.post('/api/v1/iac/scans', data),

  // Drift & Exposure
  getDriftRecords: (params?: Record<string, string | number>) =>
    apiClient.get('/api/v1/drift', { params }),
  getExposureAlerts: () => apiClient.get('/api/v1/exposure/alerts'),

  // Admin
  getHealth: () => apiClient.get('/api/v1/admin/health'),
  getConfiguration: () => apiClient.get('/api/v1/admin/config'),
  getStatistics: () => apiClient.get('/api/v1/admin/statistics'),
  getAuditLog: (limit?: number) => apiClient.get('/api/v1/admin/audit-log', { params: { limit } }),
  runFullScan: () => apiClient.post('/api/v1/process/run-full-scan'),
}

export default apiClient
