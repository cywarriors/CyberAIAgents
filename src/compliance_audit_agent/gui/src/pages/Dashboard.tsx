import { useQuery } from '@tanstack/react-query'
import api from '../api/client'

export default function Dashboard() {
  const { data, isLoading } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => api.get('/dashboard/compliance').then(r => r.data),
    refetchInterval: 30000,
  })

  if (isLoading) return <div className="text-gray-400">Loading dashboard…</div>

  const scores: Record<string, any> = data?.framework_scores || {}
  const frameworks = Object.keys(scores)

  return (
    <div>
      <h1 className="text-xl font-bold text-green-400 mb-6">Compliance Dashboard</h1>
      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className="bg-gray-800 rounded p-4">
          <div className="text-xs text-gray-400 mb-1">Overall Compliance</div>
          <div className="text-3xl font-bold text-green-400">{(data?.overall_compliance ?? 0).toFixed(1)}%</div>
        </div>
        <div className="bg-gray-800 rounded p-4">
          <div className="text-xs text-gray-400 mb-1">Total Gaps</div>
          <div className="text-3xl font-bold text-yellow-400">{data?.total_gaps ?? 0}</div>
        </div>
        <div className="bg-gray-800 rounded p-4">
          <div className="text-xs text-gray-400 mb-1">Critical Gaps</div>
          <div className="text-3xl font-bold text-red-400">{data?.critical_gaps ?? 0}</div>
        </div>
        <div className="bg-gray-800 rounded p-4">
          <div className="text-xs text-gray-400 mb-1">Audit Packs</div>
          <div className="text-3xl font-bold text-blue-400">{data?.audit_packs_generated ?? 0}</div>
        </div>
      </div>
      <h2 className="text-sm font-semibold text-gray-300 mb-3">Framework Scores</h2>
      <div className="space-y-2">
        {frameworks.map(fw => (
          <div key={fw} className="bg-gray-800 rounded p-3 flex items-center gap-4">
            <span className="text-sm text-gray-300 w-28">{fw}</span>
            <div className="flex-1 bg-gray-700 rounded h-2">
              <div
                className="bg-green-500 h-2 rounded"
                style={{ width: `${scores[fw]?.score ?? 0}%` }}
              />
            </div>
            <span className="text-sm text-green-400 w-16 text-right">{(scores[fw]?.score ?? 0).toFixed(1)}%</span>
          </div>
        ))}
        {frameworks.length === 0 && <p className="text-gray-500 text-sm">No framework scores yet.</p>}
      </div>
    </div>
  )
}
