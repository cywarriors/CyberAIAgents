import { useEffect, useState } from 'react'
import { cspmApi } from '../api/client'
import { Cloud, Shield, ChevronRight } from 'lucide-react'

const PROVIDER_COLORS: Record<string, string> = {
  aws: '#ff9900', azure: '#0078d4', gcp: '#4285f4',
}

export default function AccountSubscriptionView() {
  const [accounts, setAccounts] = useState<any[]>([])
  const [selectedAccount, setSelectedAccount] = useState<string | null>(null)
  const [resources, setResources] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    cspmApi.listAccounts().then(r => { setAccounts(r.data); setLoading(false) })
      .catch(() => setLoading(false))
  }, [])

  const loadResources = async (accountId: string) => {
    setSelectedAccount(accountId)
    try {
      const res = await cspmApi.getAccountResources(accountId)
      setResources(res.data)
    } catch (e) { console.error(e) }
  }

  if (loading) return <div className="text-center py-12">Loading accounts...</div>

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-bold text-gray-900 flex items-center gap-2">
        <Cloud size={24} /> Accounts & Subscriptions
      </h2>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Account list */}
        <div className="space-y-3">
          {accounts.map((a) => (
            <div
              key={a.account_id}
              onClick={() => loadResources(a.account_id)}
              className={`bg-white p-5 rounded-lg shadow-sm cursor-pointer border-l-4 transition hover:shadow-md ${
                selectedAccount === a.account_id ? 'border-cyan-500 ring-2 ring-cyan-200' : 'border-gray-200'
              }`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-semibold text-gray-900">{a.account_name}</h3>
                  <p className="text-xs text-gray-500">{a.account_id} &middot; <span className="uppercase font-semibold" style={{ color: PROVIDER_COLORS[a.provider] }}>{a.provider}</span> &middot; {a.environment}</p>
                </div>
                <ChevronRight size={20} className="text-gray-400" />
              </div>
              <div className="mt-3 grid grid-cols-4 gap-2 text-center text-xs">
                <div><p className="text-gray-500">Resources</p><p className="font-bold text-lg">{a.total_resources}</p></div>
                <div><p className="text-gray-500">Findings</p><p className="font-bold text-lg">{a.total_findings}</p></div>
                <div><p className="text-gray-500">Critical</p><p className="font-bold text-lg text-red-600">{a.critical_findings}</p></div>
                <div><p className="text-gray-500">Compliance</p><p className="font-bold text-lg text-green-600">{a.compliance_score}%</p></div>
              </div>
            </div>
          ))}
        </div>

        {/* Resource inventory for selected account */}
        <div className="bg-white rounded-lg shadow-sm">
          {!selectedAccount ? (
            <div className="text-center py-16 text-gray-400">Select an account to view resources</div>
          ) : (
            <>
              <div className="px-6 py-4 border-b"><h3 className="font-semibold">Resources &mdash; {selectedAccount}</h3></div>
              <table className="w-full text-sm">
                <thead className="bg-gray-50 border-b"><tr>
                  <th className="text-left px-4 py-3">Name</th>
                  <th className="text-left px-4 py-3">Type</th>
                  <th className="text-left px-4 py-3">Region</th>
                  <th className="text-left px-4 py-3">Exposure</th>
                  <th className="text-left px-4 py-3">Criticality</th>
                </tr></thead>
                <tbody>
                  {resources.map((r: any) => (
                    <tr key={r.resource_id} className="border-b">
                      <td className="px-4 py-3 font-medium">{r.resource_name}</td>
                      <td className="px-4 py-3 text-gray-600">{r.resource_type}</td>
                      <td className="px-4 py-3">{r.region}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 rounded text-xs font-semibold ${
                          r.exposure === 'internet_facing' ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'
                        }`}>{r.exposure}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 rounded text-xs font-semibold ${
                          r.criticality === 'critical' ? 'bg-red-100 text-red-800'
                            : r.criticality === 'high' ? 'bg-orange-100 text-orange-800' : 'bg-yellow-100 text-yellow-800'
                        }`}>{r.criticality}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
