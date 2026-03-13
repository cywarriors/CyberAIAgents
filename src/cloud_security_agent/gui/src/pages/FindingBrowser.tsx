import { useEffect, useState } from 'react'
import { cspmApi } from '../api/client'
import { AlertCircle, Search, Filter } from 'lucide-react'

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-green-100 text-green-800',
  info: 'bg-blue-100 text-blue-800',
}

const STATUS_BADGE: Record<string, string> = {
  open: 'bg-red-100 text-red-700',
  in_progress: 'bg-yellow-100 text-yellow-700',
  remediated: 'bg-green-100 text-green-700',
  risk_accepted: 'bg-gray-100 text-gray-700',
  deferred: 'bg-blue-100 text-blue-700',
}

export default function FindingBrowser() {
  const [findings, setFindings] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState<Record<string, string>>({})
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<any>(null)

  const loadFindings = async () => {
    setLoading(true)
    try {
      const params: Record<string, string | number> = { page, page_size: 20 }
      Object.entries(filters).forEach(([k, v]) => { if (v) params[k] = v })
      const res = await cspmApi.listFindings(params)
      setFindings(res.data)
    } catch (e) {
      console.error('Failed to load findings:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadFindings() }, [page, filters])

  const loadDetail = async (id: string) => {
    try {
      const res = await cspmApi.getFindingDetail(id)
      setSelected(res.data)
    } catch (e) { console.error('Failed to load detail:', e) }
  }

  const updateStatus = async (id: string, status: string) => {
    try {
      await cspmApi.updateFindingStatus(id, status)
      loadFindings()
      if (selected?.finding_id === id) setSelected({ ...selected, remediation_status: status })
    } catch (e) { console.error('Status update failed:', e) }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-gray-900 flex items-center gap-2">
          <AlertCircle size={24} /> Misconfiguration Findings
        </h2>
      </div>

      {/* Filters */}
      <div className="bg-white p-4 rounded-lg shadow-sm flex flex-wrap gap-4 items-center">
        <Filter size={18} className="text-gray-500" />
        <select className="border rounded px-3 py-2 text-sm" value={filters.severity || ''} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
          <option value="">All Severities</option>
          {['critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="border rounded px-3 py-2 text-sm" value={filters.provider || ''} onChange={(e) => setFilters({ ...filters, provider: e.target.value })}>
          <option value="">All Providers</option>
          {['aws', 'azure', 'gcp'].map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
        </select>
        <select className="border rounded px-3 py-2 text-sm" value={filters.remediation_status || ''} onChange={(e) => setFilters({ ...filters, remediation_status: e.target.value })}>
          <option value="">All Statuses</option>
          {['open', 'in_progress', 'remediated', 'risk_accepted', 'deferred'].map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
        </select>
      </div>

      <div className="flex gap-6">
        {/* Findings Table */}
        <div className="flex-1 bg-white rounded-lg shadow-sm overflow-hidden">
          {loading ? (
            <div className="text-center py-12">Loading findings...</div>
          ) : findings.length === 0 ? (
            <div className="text-center py-12 text-gray-500">No findings match the current filters.</div>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-gray-50 border-b">
                <tr>
                  <th className="text-left px-4 py-3">Rule</th>
                  <th className="text-left px-4 py-3">Resource</th>
                  <th className="text-left px-4 py-3">Provider</th>
                  <th className="text-left px-4 py-3">Severity</th>
                  <th className="text-left px-4 py-3">Score</th>
                  <th className="text-left px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f: any) => (
                  <tr key={f.finding_id} className="border-b hover:bg-gray-50 cursor-pointer" onClick={() => loadDetail(f.finding_id)}>
                    <td className="px-4 py-3 font-medium">{f.rule_name}</td>
                    <td className="px-4 py-3 text-gray-600">{f.resource_name}</td>
                    <td className="px-4 py-3 uppercase text-xs font-semibold">{f.provider}</td>
                    <td className="px-4 py-3"><span className={`px-2 py-1 rounded text-xs font-semibold ${SEVERITY_BADGE[f.severity]}`}>{f.severity}</span></td>
                    <td className="px-4 py-3 font-mono">{f.risk_score?.toFixed(1)}</td>
                    <td className="px-4 py-3"><span className={`px-2 py-1 rounded text-xs font-semibold ${STATUS_BADGE[f.remediation_status]}`}>{f.remediation_status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {/* Pagination */}
          <div className="flex items-center justify-between px-4 py-3 border-t">
            <button disabled={page <= 1} onClick={() => setPage(p => p - 1)} className="px-3 py-1.5 border rounded text-sm disabled:opacity-40">Previous</button>
            <span className="text-sm text-gray-600">Page {page}</span>
            <button onClick={() => setPage(p => p + 1)} className="px-3 py-1.5 border rounded text-sm" disabled={findings.length < 20}>Next</button>
          </div>
        </div>

        {/* Detail Panel */}
        {selected && (
          <div className="w-96 bg-white rounded-lg shadow-sm p-6 space-y-4 overflow-y-auto max-h-[80vh]">
            <div className="flex items-center justify-between">
              <h3 className="font-bold text-lg">{selected.rule_name}</h3>
              <button onClick={() => setSelected(null)} className="text-gray-400 hover:text-gray-600">&times;</button>
            </div>
            <p className="text-sm text-gray-600">{selected.description}</p>

            <div className="grid grid-cols-2 gap-2 text-sm">
              <div><span className="text-gray-500">Resource:</span><br />{selected.resource_name}</div>
              <div><span className="text-gray-500">Type:</span><br />{selected.resource_type}</div>
              <div><span className="text-gray-500">Provider:</span><br />{selected.provider?.toUpperCase()}</div>
              <div><span className="text-gray-500">Region:</span><br />{selected.region}</div>
              <div><span className="text-gray-500">Risk Score:</span><br /><span className="font-mono font-bold">{selected.risk_score?.toFixed(1)}</span></div>
              <div><span className="text-gray-500">Tier:</span><br />{selected.risk_tier}</div>
              <div><span className="text-gray-500">Framework:</span><br />{selected.framework}</div>
              <div><span className="text-gray-500">Control:</span><br />{selected.control_id}</div>
            </div>

            <div>
              <p className="text-sm font-semibold text-gray-700 mb-1">Remediation Guidance</p>
              <p className="text-sm text-gray-600 bg-gray-50 p-3 rounded">{selected.remediation_guidance}</p>
            </div>

            {selected.cli_fix_command && (
              <div>
                <p className="text-sm font-semibold text-gray-700 mb-1">CLI Fix</p>
                <code className="block text-xs bg-gray-900 text-green-400 p-3 rounded overflow-x-auto">{selected.cli_fix_command}</code>
              </div>
            )}

            {selected.iac_fix_snippet && (
              <div>
                <p className="text-sm font-semibold text-gray-700 mb-1">IaC Fix Snippet</p>
                <pre className="text-xs bg-gray-900 text-green-400 p-3 rounded overflow-x-auto whitespace-pre-wrap">{selected.iac_fix_snippet}</pre>
              </div>
            )}

            <div>
              <p className="text-sm font-semibold text-gray-700 mb-2">Update Status</p>
              <div className="flex flex-wrap gap-2">
                {['open', 'in_progress', 'remediated', 'risk_accepted', 'deferred'].map(s => (
                  <button key={s} onClick={() => updateStatus(selected.finding_id, s)}
                    className={`px-3 py-1.5 text-xs rounded font-medium transition ${
                      selected.remediation_status === s ? 'bg-cyan-600 text-white' : 'bg-gray-100 hover:bg-gray-200 text-gray-700'
                    }`}>
                    {s.replace('_', ' ')}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
