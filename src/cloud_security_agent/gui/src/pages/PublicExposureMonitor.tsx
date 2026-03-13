import { useEffect, useState } from 'react'
import { cspmApi } from '../api/client'
import { Globe, AlertTriangle } from 'lucide-react'

const EXPOSURE_COLORS: Record<string, string> = {
  public: 'bg-red-100 text-red-800',
  internet_facing: 'bg-orange-100 text-orange-800',
  internal: 'bg-green-100 text-green-800',
  private: 'bg-green-100 text-green-800',
}

const PROVIDER_COLORS: Record<string, string> = {
  aws: '#ff9900', azure: '#0078d4', gcp: '#4285f4',
}

export default function PublicExposureMonitor() {
  const [alerts, setAlerts] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    cspmApi.getExposureAlerts().then(r => { setAlerts(r.data); setLoading(false) }).catch(() => setLoading(false))
  }, [])

  if (loading) return <div className="text-center py-12">Loading exposure data...</div>

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-bold text-gray-900 flex items-center gap-2">
        <Globe size={24} /> Public Exposure Monitor
      </h2>

      {/* Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white p-5 rounded-lg shadow-sm border-l-4 border-red-500">
          <p className="text-gray-600 text-sm">Total Exposure Alerts</p>
          <p className="text-3xl font-bold text-red-600">{alerts.length}</p>
        </div>
        <div className="bg-white p-5 rounded-lg shadow-sm border-l-4 border-orange-500">
          <p className="text-gray-600 text-sm">Public Resources</p>
          <p className="text-3xl font-bold text-orange-600">{alerts.filter(a => a.exposure_level === 'public').length}</p>
        </div>
        <div className="bg-white p-5 rounded-lg shadow-sm border-l-4 border-yellow-500">
          <p className="text-gray-600 text-sm">Avg Risk Score</p>
          <p className="text-3xl font-bold">{(alerts.reduce((s, a) => s + a.risk_score, 0) / (alerts.length || 1)).toFixed(1)}</p>
        </div>
      </div>

      {/* Alert Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {alerts.sort((a, b) => b.risk_score - a.risk_score).map((alert: any) => (
          <div key={alert.resource_id} className="bg-white p-6 rounded-lg shadow-sm border-l-4 border-red-400 hover:shadow-md transition">
            <div className="flex items-start justify-between mb-3">
              <div>
                <h3 className="font-semibold text-gray-900">{alert.resource_name}</h3>
                <p className="text-xs text-gray-500 font-mono">{alert.resource_id}</p>
              </div>
              <span className="text-2xl font-bold text-red-600">{alert.risk_score}</span>
            </div>

            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <span className="text-gray-500">Type:</span>
                <span className="ml-1 font-medium">{alert.resource_type}</span>
              </div>
              <div>
                <span className="text-gray-500">Provider:</span>
                <span className="ml-1 font-semibold uppercase" style={{ color: PROVIDER_COLORS[alert.provider] }}>{alert.provider}</span>
              </div>
              <div>
                <span className="text-gray-500">Region:</span>
                <span className="ml-1">{alert.region}</span>
              </div>
              <div>
                <span className="text-gray-500">Account:</span>
                <span className="ml-1">{alert.account_id}</span>
              </div>
              <div>
                <span className="text-gray-500">Exposure:</span>
                <span className={`ml-1 px-2 py-0.5 rounded text-xs font-semibold ${EXPOSURE_COLORS[alert.exposure_level]}`}>
                  {alert.exposure_level}
                </span>
              </div>
              <div>
                <span className="text-gray-500">Blast Radius:</span>
                <span className="ml-1 font-medium">{alert.blast_radius}</span>
              </div>
            </div>

            <div className="mt-3 flex items-center gap-2 text-sm text-red-600">
              <AlertTriangle size={14} />
              <span>{alert.associated_findings} associated finding(s)</span>
            </div>
          </div>
        ))}
      </div>

      {alerts.length === 0 && (
        <div className="bg-white p-12 rounded-lg shadow-sm text-center text-gray-400">
          No public exposure alerts found
        </div>
      )}
    </div>
  )
}
