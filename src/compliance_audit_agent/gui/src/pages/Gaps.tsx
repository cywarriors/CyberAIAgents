import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import api from '../api/client'

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-blue-400',
}

export default function Gaps() {
  const [severity, setSeverity] = useState('')
  const { data, isLoading } = useQuery({
    queryKey: ['gaps', severity],
    queryFn: () => api.get(`/gaps${severity ? `?severity=${severity}` : ''}`).then(r => r.data),
  })
  const items: any[] = data?.items ?? []
  return (
    <div>
      <h1 className="text-xl font-bold text-green-400 mb-4">Compliance Gaps</h1>
      <div className="flex gap-2 mb-4">
        {['', 'critical', 'high', 'medium', 'low'].map(s => (
          <button key={s} onClick={() => setSeverity(s)}
            className={`px-3 py-1 rounded text-xs ${severity === s ? 'bg-green-700 text-white' : 'bg-gray-700 text-gray-300'}`}>
            {s || 'All'}
          </button>
        ))}
      </div>
      {isLoading ? <div className="text-gray-400">Loading…</div> : (
        <div className="space-y-2">
          {items.map(g => (
            <div key={g.gap_id} className="bg-gray-800 rounded p-3">
              <div className="flex items-center gap-3 mb-1">
                <span className={`text-xs font-bold uppercase ${SEV_COLOR[g.severity] ?? 'text-gray-400'}`}>{g.severity}</span>
                <span className="text-sm text-gray-200">{g.control_id}</span>
                <span className="text-xs text-green-300">{g.framework}</span>
              </div>
              <p className="text-xs text-gray-400 mb-1">{g.description}</p>
              <p className="text-xs text-blue-300">{g.remediation_guidance}</p>
            </div>
          ))}
          {items.length === 0 && <p className="text-gray-500 text-sm">No gaps found.</p>}
          <p className="text-xs text-gray-500">Total: {data?.total ?? 0}</p>
        </div>
      )}
    </div>
  )
}
