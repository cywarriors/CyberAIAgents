import { useEffect, useState } from 'react'
import { cspmApi } from '../api/client'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, Legend,
} from 'recharts'
import { Shield, AlertTriangle, Cloud, GitCompareArrows, Code2, Globe } from 'lucide-react'

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444', high: '#f59e0b', medium: '#eab308', low: '#10b981',
}
const PROVIDER_COLORS: Record<string, string> = {
  aws: '#ff9900', azure: '#0078d4', gcp: '#4285f4',
}

export default function CloudPostureDashboard() {
  const [posture, setPosture] = useState<any>(null)
  const [trend, setTrend] = useState<any[]>([])
  const [serviceData, setServiceData] = useState<any[]>([])
  const [providerSummary, setProviderSummary] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const [pRes, tRes, sRes, prRes] = await Promise.all([
          cspmApi.getPostureDashboard(),
          cspmApi.getComplianceTrend(),
          cspmApi.getFindingsByService(),
          cspmApi.getProviderSummary(),
        ])
        setPosture(pRes.data)
        setTrend(tRes.data.data)
        setServiceData(sRes.data)
        setProviderSummary(prRes.data)
      } catch (e) {
        console.error('Dashboard load failed:', e)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  if (loading) return <div className="text-center py-12">Loading dashboard...</div>

  const severityPie = posture
    ? Object.entries(posture.findings_by_severity).map(([name, value]) => ({ name, value }))
    : []

  const providerPie = posture
    ? Object.entries(posture.findings_by_provider).map(([name, value]) => ({ name, value }))
    : []

  return (
    <div className="space-y-6">
      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-4">
        <KpiCard icon={Cloud} color="blue" label="Accounts" value={posture?.total_accounts} />
        <KpiCard icon={Shield} color="cyan" label="Resources" value={posture?.total_resources?.toLocaleString()} />
        <KpiCard icon={AlertTriangle} color="red" label="Findings" value={posture?.total_findings} />
        <KpiCard icon={Shield} color="green" label="Compliance" value={`${posture?.overall_compliance_score}%`} />
        <KpiCard icon={Globe} color="orange" label="Public Exposed" value={posture?.public_exposure_count} />
        <KpiCard icon={GitCompareArrows} color="purple" label="Drift (24h)" value={posture?.drift_count_24h} />
      </div>

      {/* IaC Gate Summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-white p-6 rounded-lg shadow-sm border-l-4 border-indigo-500">
          <div className="flex items-center gap-3">
            <Code2 size={28} className="text-indigo-500" />
            <div>
              <p className="text-gray-600 text-sm">IaC Scans</p>
              <p className="text-2xl font-bold">{posture?.iac_scans_count}</p>
            </div>
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border-l-4 border-emerald-500">
          <div className="flex items-center gap-3">
            <Shield size={28} className="text-emerald-500" />
            <div>
              <p className="text-gray-600 text-sm">IaC Block Rate</p>
              <p className="text-2xl font-bold">{posture?.iac_block_rate}%</p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="bg-white p-6 rounded-lg shadow-sm">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Findings by Severity</h2>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie data={severityPie} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={100} label>
                {severityPie.map((entry) => (
                  <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || '#94a3b8'} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* By Provider */}
        <div className="bg-white p-6 rounded-lg shadow-sm">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Findings by Provider</h2>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie data={providerPie} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={100} label>
                {providerPie.map((entry) => (
                  <Cell key={entry.name} fill={PROVIDER_COLORS[entry.name] || '#94a3b8'} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Compliance Trend */}
      <div className="bg-white p-6 rounded-lg shadow-sm">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Compliance Score Trend (30d)</h2>
        <ResponsiveContainer width="100%" height={280}>
          <LineChart data={trend}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="date" />
            <YAxis domain={[60, 100]} />
            <Tooltip />
            <Line type="monotone" dataKey="score" stroke="#06b6d4" strokeWidth={2} dot={{ r: 4 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Findings by Service */}
      <div className="bg-white p-6 rounded-lg shadow-sm">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Findings by Cloud Service</h2>
        <ResponsiveContainer width="100%" height={350}>
          <BarChart data={serviceData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="service" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Bar dataKey="critical" stackId="a" fill="#ef4444" />
            <Bar dataKey="high" stackId="a" fill="#f59e0b" />
            <Bar dataKey="medium" stackId="a" fill="#eab308" />
            <Bar dataKey="low" stackId="a" fill="#10b981" />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Provider Summary Cards */}
      {providerSummary && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {Object.entries(providerSummary).map(([provider, data]: [string, any]) => (
            <div key={provider} className="bg-white p-6 rounded-lg shadow-sm">
              <h3 className="text-lg font-semibold uppercase mb-3" style={{ color: PROVIDER_COLORS[provider] }}>
                {provider}
              </h3>
              <div className="space-y-2 text-sm text-gray-700">
                <div className="flex justify-between"><span>Accounts</span><span className="font-semibold">{data.accounts}</span></div>
                <div className="flex justify-between"><span>Resources</span><span className="font-semibold">{data.resources.toLocaleString()}</span></div>
                <div className="flex justify-between"><span>Findings</span><span className="font-semibold">{data.findings}</span></div>
                <div className="flex justify-between"><span>Compliance</span><span className="font-semibold">{data.compliance_score}%</span></div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Top Non-Compliant Services */}
      <div className="bg-white p-6 rounded-lg shadow-sm">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Top Non-Compliant Services</h2>
        <table className="w-full text-sm">
          <thead><tr className="border-b text-left text-gray-600"><th className="pb-2">Service</th><th className="pb-2">Provider</th><th className="pb-2">Findings</th></tr></thead>
          <tbody>
            {posture?.top_non_compliant_services?.map((s: any, i: number) => (
              <tr key={i} className="border-b last:border-0">
                <td className="py-2 font-medium">{s.service}</td>
                <td className="py-2 uppercase text-xs font-semibold" style={{ color: PROVIDER_COLORS[s.provider] }}>{s.provider}</td>
                <td className="py-2">{s.finding_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function KpiCard({ icon: Icon, color, label, value }: { icon: any; color: string; label: string; value: any }) {
  const borderColor: Record<string, string> = {
    blue: 'border-blue-500', cyan: 'border-cyan-500', red: 'border-red-500',
    green: 'border-green-500', orange: 'border-orange-500', purple: 'border-purple-500',
  }
  const textColor: Record<string, string> = {
    blue: 'text-blue-500', cyan: 'text-cyan-500', red: 'text-red-500',
    green: 'text-green-500', orange: 'text-orange-500', purple: 'text-purple-500',
  }
  return (
    <div className={`bg-white p-5 rounded-lg shadow-sm border-l-4 ${borderColor[color]}`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-gray-600 text-sm">{label}</p>
          <p className="text-2xl font-bold text-gray-900">{value}</p>
        </div>
        <Icon size={32} className={`${textColor[color]} opacity-20`} />
      </div>
    </div>
  )
}
