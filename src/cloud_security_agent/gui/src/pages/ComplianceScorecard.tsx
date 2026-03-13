import { useEffect, useState } from 'react'
import { cspmApi } from '../api/client'
import { CheckCircle2, XCircle, Minus } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'

const TREND_ICON: Record<string, any> = {
  improving: <span className="text-green-500 text-xs font-semibold">▲ Improving</span>,
  declining: <span className="text-red-500 text-xs font-semibold">▼ Declining</span>,
  stable: <span className="text-gray-500 text-xs font-semibold">— Stable</span>,
}

export default function ComplianceScorecard() {
  const [scores, setScores] = useState<any[]>([])
  const [controls, setControls] = useState<any[]>([])
  const [framework, setFramework] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const [sRes, cRes] = await Promise.all([
          cspmApi.getComplianceScores(framework ? { framework } : undefined),
          cspmApi.getComplianceControls(framework ? { framework } : undefined),
        ])
        setScores(sRes.data)
        setControls(cRes.data)
      } catch (e) { console.error(e) }
      finally { setLoading(false) }
    }
    load()
  }, [framework])

  if (loading) return <div className="text-center py-12">Loading compliance data...</div>

  const chartData = scores.map(s => ({
    label: `${s.account_id.replace(/-/g, ' ').slice(0, 16)} (${s.framework})`,
    passed: s.passed_controls,
    failed: s.failed_controls,
  }))

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-gray-900 flex items-center gap-2">
          <CheckCircle2 size={24} /> Compliance Scorecard
        </h2>
        <select className="border rounded px-3 py-2 text-sm" value={framework} onChange={e => setFramework(e.target.value)}>
          <option value="">All Frameworks</option>
          <option value="CIS">CIS Benchmarks</option>
          <option value="NIST">NIST 800-53</option>
        </select>
      </div>

      {/* Score Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {scores.map((s, i) => (
          <div key={i} className="bg-white p-5 rounded-lg shadow-sm">
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold text-sm text-gray-700">{s.account_id}</h3>
              <span className="text-xs px-2 py-1 bg-blue-100 text-blue-700 rounded font-semibold">{s.framework}</span>
            </div>
            <div className="flex items-center gap-3 mb-2">
              <p className="text-3xl font-bold text-gray-900">{s.score_percent.toFixed(1)}%</p>
              {TREND_ICON[s.score_trend]}
            </div>
            <div className="flex justify-between text-sm text-gray-500">
              <span className="text-green-600">{s.passed_controls} passed</span>
              <span className="text-red-600">{s.failed_controls} failed</span>
              <span>{s.total_controls} total</span>
            </div>
            {/* Progress bar */}
            <div className="mt-2 h-2 bg-gray-200 rounded-full overflow-hidden">
              <div className="h-full bg-green-500 rounded-full" style={{ width: `${s.score_percent}%` }} />
            </div>
          </div>
        ))}
      </div>

      {/* Chart */}
      <div className="bg-white p-6 rounded-lg shadow-sm">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Controls Pass/Fail by Account</h3>
        <ResponsiveContainer width="100%" height={320}>
          <BarChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="label" tick={{ fontSize: 10 }} angle={-25} textAnchor="end" height={80} />
            <YAxis />
            <Tooltip />
            <Legend />
            <Bar dataKey="passed" fill="#22c55e" />
            <Bar dataKey="failed" fill="#ef4444" />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Control-Level Detail */}
      <div className="bg-white rounded-lg shadow-sm">
        <div className="px-6 py-4 border-b"><h3 className="font-semibold">Control-Level Detail</h3></div>
        <table className="w-full text-sm">
          <thead className="bg-gray-50 border-b"><tr>
            <th className="text-left px-4 py-3">Control ID</th>
            <th className="text-left px-4 py-3">Control Name</th>
            <th className="text-left px-4 py-3">Status</th>
            <th className="text-left px-4 py-3">Severity</th>
            <th className="text-left px-4 py-3">Affected</th>
          </tr></thead>
          <tbody>
            {controls.map((c: any, i: number) => (
              <tr key={i} className="border-b">
                <td className="px-4 py-3 font-mono text-xs">{c.control_id}</td>
                <td className="px-4 py-3 font-medium">{c.control_name}</td>
                <td className="px-4 py-3">
                  {c.status === 'pass'
                    ? <span className="flex items-center gap-1 text-green-600"><CheckCircle2 size={14} /> Pass</span>
                    : <span className="flex items-center gap-1 text-red-600"><XCircle size={14} /> Fail</span>}
                </td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-1 rounded text-xs font-semibold ${
                    c.severity === 'critical' ? 'bg-red-100 text-red-800'
                    : c.severity === 'high' ? 'bg-orange-100 text-orange-800' : 'bg-yellow-100 text-yellow-800'
                  }`}>{c.severity}</span>
                </td>
                <td className="px-4 py-3">{c.affected_resources}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
