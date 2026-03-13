import { useEffect, useState } from 'react'
import { cspmApi } from '../api/client'
import { Settings, Play, RefreshCw, Shield, Activity, FileText } from 'lucide-react'

export default function Administration() {
  const [health, setHealth] = useState<any>(null)
  const [config, setConfig] = useState<any>(null)
  const [stats, setStats] = useState<any>(null)
  const [auditLog, setAuditLog] = useState<any>(null)
  const [scanResult, setScanResult] = useState<any>(null)
  const [scanning, setScanning] = useState(false)
  const [activeTab, setActiveTab] = useState<'health' | 'config' | 'stats' | 'audit'>('health')

  useEffect(() => {
    const load = async () => {
      try {
        const [hRes, cRes, sRes, aRes] = await Promise.all([
          cspmApi.getHealth(),
          cspmApi.getConfiguration(),
          cspmApi.getStatistics(),
          cspmApi.getAuditLog(20),
        ])
        setHealth(hRes.data)
        setConfig(cRes.data)
        setStats(sRes.data)
        setAuditLog(aRes.data)
      } catch (e) { console.error(e) }
    }
    load()
  }, [])

  const triggerScan = async () => {
    setScanning(true)
    setScanResult(null)
    try {
      const res = await cspmApi.runFullScan()
      setScanResult(res.data)
    } catch (e) { console.error(e) }
    finally { setScanning(false) }
  }

  const tabs = [
    { id: 'health' as const, label: 'Health', icon: Activity },
    { id: 'config' as const, label: 'Configuration', icon: Settings },
    { id: 'stats' as const, label: 'Statistics', icon: Shield },
    { id: 'audit' as const, label: 'Audit Log', icon: FileText },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-gray-900 flex items-center gap-2">
          <Settings size={24} /> Administration
        </h2>
        <button onClick={triggerScan} disabled={scanning}
          className="px-4 py-2 bg-cyan-600 text-white rounded-lg text-sm hover:bg-cyan-700 transition flex items-center gap-2 disabled:opacity-50">
          {scanning ? <RefreshCw size={16} className="animate-spin" /> : <Play size={16} />}
          {scanning ? 'Scanning...' : 'Run Full Scan'}
        </button>
      </div>

      {/* Scan Result */}
      {scanResult && (
        <div className={`p-4 rounded-lg ${scanResult.success ? 'bg-green-50 border border-green-200' : 'bg-red-50 border border-red-200'}`}>
          <p className="font-semibold">{scanResult.success ? 'Scan completed successfully' : 'Scan failed'}</p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm mt-2">
            <span>Resources: {scanResult.total_resources_scanned}</span>
            <span>Findings: {scanResult.total_findings}</span>
            <span>Critical: {scanResult.critical_findings}</span>
            <span>Tickets: {scanResult.tickets_created}</span>
          </div>
          {scanResult.errors?.length > 0 && (
            <p className="text-sm text-red-600 mt-1">Errors: {scanResult.errors.join(', ')}</p>
          )}
        </div>
      )}

      {/* Tab Navigation */}
      <div className="flex gap-2 border-b">
        {tabs.map(t => {
          const Icon = t.icon
          return (
            <button key={t.id} onClick={() => setActiveTab(t.id)}
              className={`px-4 py-2.5 text-sm font-medium flex items-center gap-2 border-b-2 transition ${
                activeTab === t.id ? 'border-cyan-600 text-cyan-600' : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}>
              <Icon size={16} /> {t.label}
            </button>
          )
        })}
      </div>

      {/* Health Tab */}
      {activeTab === 'health' && health && (
        <div className="bg-white p-6 rounded-lg shadow-sm">
          <div className="flex items-center gap-3 mb-4">
            <span className={`h-4 w-4 rounded-full ${health.status === 'healthy' ? 'bg-green-500' : 'bg-red-500'}`} />
            <h3 className="text-lg font-semibold">{health.status === 'healthy' ? 'All Systems Healthy' : 'Issues Detected'}</h3>
          </div>
          <p className="text-gray-600 mb-4">{health.message}</p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(health.components || {}).map(([name, status]) => (
              <div key={name} className="border rounded p-3">
                <p className="text-sm text-gray-600">{name}</p>
                <p className={`font-semibold ${status === 'healthy' ? 'text-green-600' : 'text-red-600'}`}>{status as string}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Config Tab */}
      {activeTab === 'config' && config && (
        <div className="bg-white p-6 rounded-lg shadow-sm">
          {Object.entries(config).map(([section, values]) => (
            <div key={section} className="mb-6">
              <h3 className="text-md font-semibold text-gray-800 mb-2 capitalize">{section.replace(/_/g, ' ')}</h3>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-2 text-sm">
                {typeof values === 'object' && values !== null
                  ? Object.entries(values as Record<string, any>).map(([k, v]) => (
                      <div key={k} className="border rounded p-2">
                        <p className="text-gray-500 text-xs">{k.replace(/_/g, ' ')}</p>
                        <p className="font-medium">{String(v)}</p>
                      </div>
                    ))
                  : <div className="border rounded p-2"><p className="text-gray-500 text-xs">{section}</p><p className="font-medium">{String(values)}</p></div>}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Stats Tab */}
      {activeTab === 'stats' && stats && (
        <div className="bg-white p-6 rounded-lg shadow-sm">
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
            {Object.entries(stats).map(([key, value]) => (
              <div key={key} className="border rounded-lg p-4">
                <p className="text-xs text-gray-500 capitalize">{key.replace(/_/g, ' ')}</p>
                <p className="text-2xl font-bold text-gray-900">{typeof value === 'number' ? value.toLocaleString() : String(value)}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Audit Tab */}
      {activeTab === 'audit' && auditLog && (
        <div className="bg-white rounded-lg shadow-sm overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b"><tr>
              <th className="text-left px-4 py-3">Timestamp</th>
              <th className="text-left px-4 py-3">Action</th>
              <th className="text-left px-4 py-3">User</th>
              <th className="text-left px-4 py-3">Details</th>
            </tr></thead>
            <tbody>
              {auditLog.entries?.map((e: any, i: number) => (
                <tr key={i} className="border-b">
                  <td className="px-4 py-3 text-xs text-gray-500 whitespace-nowrap">{new Date(e.timestamp).toLocaleString()}</td>
                  <td className="px-4 py-3 font-mono text-xs">{e.action}</td>
                  <td className="px-4 py-3">{e.user}</td>
                  <td className="px-4 py-3 text-gray-600">{e.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="px-4 py-3 border-t text-sm text-gray-500">
            Showing {auditLog.showing} of {auditLog.total_entries?.toLocaleString()} entries
          </div>
        </div>
      )}
    </div>
  )
}
