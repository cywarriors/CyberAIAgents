import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import api from '../api/client'

export default function Evidence() {
  const [page, setPage] = useState(1)
  const [framework, setFramework] = useState('')
  const { data, isLoading } = useQuery({
    queryKey: ['evidence', page, framework],
    queryFn: () => api.get(`/evidence?page=${page}&page_size=20${framework ? `&framework=${framework}` : ''}`).then(r => r.data),
  })
  const items: any[] = data?.items ?? []
  return (
    <div>
      <h1 className="text-xl font-bold text-green-400 mb-4">Evidence Items</h1>
      <div className="flex gap-2 mb-4">
        <input className="bg-gray-800 border border-gray-700 rounded px-3 py-1 text-sm text-gray-200 w-40"
          placeholder="Framework filter" value={framework} onChange={e => { setFramework(e.target.value); setPage(1) }} />
      </div>
      {isLoading ? <div className="text-gray-400">Loading…</div> : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-gray-400 border-b border-gray-700">
                <th className="text-left py-2">ID</th><th className="text-left py-2">Source</th>
                <th className="text-left py-2">Framework</th><th className="text-left py-2">Control</th>
                <th className="text-left py-2">Type</th><th className="text-left py-2">Collected</th>
              </tr></thead>
              <tbody>{items.map(ev => (
                <tr key={ev.evidence_id} className="border-b border-gray-800 hover:bg-gray-800">
                  <td className="py-1 font-mono text-xs text-gray-400">{ev.evidence_id?.slice(0, 8)}…</td>
                  <td className="py-1 text-blue-300">{ev.source_system}</td>
                  <td className="py-1 text-green-300">{ev.framework}</td>
                  <td className="py-1 text-gray-300">{ev.control_id}</td>
                  <td className="py-1 text-gray-400">{ev.source_type}</td>
                  <td className="py-1 text-gray-500 text-xs">{ev.collected_at?.slice(0, 19)}</td>
                </tr>
              ))}</tbody>
            </table>
            {items.length === 0 && <p className="text-gray-500 text-sm mt-4">No evidence items.</p>}
          </div>
          <div className="flex gap-2 mt-3">
            <button className="px-3 py-1 bg-gray-700 rounded text-sm disabled:opacity-40" disabled={page === 1} onClick={() => setPage(p => p - 1)}>Prev</button>
            <span className="text-sm text-gray-400">Page {page}</span>
            <button className="px-3 py-1 bg-gray-700 rounded text-sm disabled:opacity-40" disabled={items.length < 20} onClick={() => setPage(p => p + 1)}>Next</button>
          </div>
        </>
      )}
    </div>
  )
}
