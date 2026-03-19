import { useQuery } from '@tanstack/react-query'
import api from '../api/client'

export default function AuditPacks() {
  const { data = [], isLoading } = useQuery({
    queryKey: ['audit-packs'],
    queryFn: () => api.get('/audit-packs').then(r => r.data),
  })
  if (isLoading) return <div className="text-gray-400">Loading…</div>
  return (
    <div>
      <h1 className="text-xl font-bold text-green-400 mb-4">Audit Packs</h1>
      <div className="space-y-3">
        {(data as any[]).map(p => (
          <div key={p.pack_id} className="bg-gray-800 rounded p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-green-300">{p.framework}</span>
              <span className={`text-xs px-2 py-0.5 rounded ${p.is_final ? 'bg-green-700' : 'bg-yellow-700'}`}>
                {p.is_final ? 'Final' : 'Pending Approval'}
              </span>
            </div>
            <div className="text-xs text-gray-400 space-y-1">
              <div>Score: <span className="text-green-400">{(p.overall_score ?? 0).toFixed(1)}%</span></div>
              <div>Evidence Items: {p.evidence_count ?? 0}</div>
              <div className="font-mono break-all">SHA-256: {p.sha256_manifest?.slice(0, 32)}…</div>
              <div>Generated: {p.generated_at?.slice(0, 19)}</div>
            </div>
          </div>
        ))}
        {data.length === 0 && <p className="text-gray-500 text-sm">No audit packs generated yet.</p>}
      </div>
    </div>
  )
}
