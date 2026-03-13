import { useEffect, useState } from 'react'
import { cspmApi } from '../api/client'
import { GitCompareArrows, AlertTriangle, ArrowUp, ArrowDown, Minus } from 'lucide-react'

const DRIFT_BADGE: Record<string, { cls: string; label: string }> = {
  security_regression: { cls: 'bg-red-100 text-red-800', label: 'Regression' },
  improvement: { cls: 'bg-green-100 text-green-800', label: 'Improvement' },
  neutral: { cls: 'bg-gray-100 text-gray-800', label: 'Neutral' },
}

const DRIFT_ICON: Record<string, any> = {
  security_regression: <ArrowDown size={14} className="text-red-500" />,
  improvement: <ArrowUp size={14} className="text-green-500" />,
  neutral: <Minus size={14} className="text-gray-500" />,
}

export default function DriftDetector() {
  const [drifts, setDrifts] = useState<any[]>([])
  const [filterType, setFilterType] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const params: Record<string, string | number> = {}
    if (filterType) params.drift_type = filterType
    cspmApi.getDriftRecords(params).then(r => { setDrifts(r.data); setLoading(false) }).catch(() => setLoading(false))
  }, [filterType])

  if (loading) return <div className="text-center py-12">Loading drift records...</div>

  const regressionCount = drifts.filter(d => d.drift_type === 'security_regression').length
  const improvementCount = drifts.filter(d => d.drift_type === 'improvement').length

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-bold text-gray-900 flex items-center gap-2">
        <GitCompareArrows size={24} /> Drift Detector
      </h2>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white p-5 rounded-lg shadow-sm border-l-4 border-gray-400">
          <p className="text-gray-600 text-sm">Total Drift Events</p>
          <p className="text-3xl font-bold">{drifts.length}</p>
        </div>
        <div className="bg-white p-5 rounded-lg shadow-sm border-l-4 border-red-500">
          <p className="text-gray-600 text-sm">Security Regressions</p>
          <p className="text-3xl font-bold text-red-600">{regressionCount}</p>
        </div>
        <div className="bg-white p-5 rounded-lg shadow-sm border-l-4 border-green-500">
          <p className="text-gray-600 text-sm">Improvements</p>
          <p className="text-3xl font-bold text-green-600">{improvementCount}</p>
        </div>
      </div>

      {/* Filter */}
      <div className="bg-white p-4 rounded-lg shadow-sm flex items-center gap-4">
        <span className="text-sm font-medium text-gray-700">Filter:</span>
        <select className="border rounded px-3 py-2 text-sm" value={filterType} onChange={e => setFilterType(e.target.value)}>
          <option value="">All Types</option>
          <option value="security_regression">Regressions Only</option>
          <option value="improvement">Improvements Only</option>
          <option value="neutral">Neutral Only</option>
        </select>
      </div>

      {/* Drift Table */}
      <div className="bg-white rounded-lg shadow-sm overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 border-b"><tr>
            <th className="text-left px-4 py-3">Resource</th>
            <th className="text-left px-4 py-3">Type</th>
            <th className="text-left px-4 py-3">Account</th>
            <th className="text-left px-4 py-3">Field Changed</th>
            <th className="text-left px-4 py-3">Previous</th>
            <th className="text-left px-4 py-3">Current</th>
            <th className="text-left px-4 py-3">Drift Type</th>
            <th className="text-left px-4 py-3">Detected</th>
          </tr></thead>
          <tbody>
            {drifts.map((d: any) => {
              const badge = DRIFT_BADGE[d.drift_type] || DRIFT_BADGE.neutral
              return (
                <tr key={d.drift_id} className="border-b hover:bg-gray-50">
                  <td className="px-4 py-3 font-mono text-xs">{d.resource_id}</td>
                  <td className="px-4 py-3">{d.resource_type}</td>
                  <td className="px-4 py-3">{d.account_id}</td>
                  <td className="px-4 py-3 font-medium">{d.field_changed}</td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-500">{d.previous_value}</td>
                  <td className="px-4 py-3 font-mono text-xs font-semibold">{d.current_value}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold ${badge.cls}`}>
                      {DRIFT_ICON[d.drift_type]} {badge.label}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500">{new Date(d.detected_at).toLocaleString()}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {drifts.length === 0 && <div className="text-center py-8 text-gray-400">No drift records found</div>}
      </div>
    </div>
  )
}
