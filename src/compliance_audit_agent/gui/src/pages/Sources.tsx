import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import api from '../api/client'

export default function Sources() {
  const qc = useQueryClient()
  const { data = [] } = useQuery({ queryKey: ['sources'], queryFn: () => api.get('/sources').then(r => r.data) })
  const [name, setName] = useState(''); const [stype, setStype] = useState('siem'); const [url, setUrl] = useState('')
  const add = useMutation({ mutationFn: () => api.post('/sources', { name, source_type: stype, api_url: url, enabled: true }), onSuccess: () => { qc.invalidateQueries({ queryKey: ['sources'] }); setName(''); setUrl('') } })
  const del = useMutation({ mutationFn: (id: string) => api.delete(`/sources/${id}`), onSuccess: () => qc.invalidateQueries({ queryKey: ['sources'] }) })
  return (
    <div>
      <h1 className="text-xl font-bold text-green-400 mb-4">Evidence Sources</h1>
      <div className="flex gap-2 mb-4">
        <input className="bg-gray-800 border border-gray-700 rounded px-3 py-1 text-sm text-gray-200 flex-1" placeholder="Source name" value={name} onChange={e => setName(e.target.value)} />
        <select className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-sm text-gray-200" value={stype} onChange={e => setStype(e.target.value)}>
          {['siem','edr','iam','cloud','grc'].map(t => <option key={t}>{t}</option>)}
        </select>
        <input className="bg-gray-800 border border-gray-700 rounded px-3 py-1 text-sm text-gray-200 flex-1" placeholder="API URL" value={url} onChange={e => setUrl(e.target.value)} />
        <button className="bg-green-700 hover:bg-green-600 px-4 py-1 rounded text-sm" onClick={() => add.mutate()} disabled={!name || !url}>Add</button>
      </div>
      <div className="space-y-2">
        {(data as any[]).map(s => (
          <div key={s.feed_id} className="bg-gray-800 rounded p-3 flex justify-between items-center">
            <div><span className="text-sm text-gray-200">{s.name}</span> <span className="text-xs text-green-300 ml-2">{s.source_type}</span></div>
            <button className="text-red-400 text-xs hover:text-red-300" onClick={() => del.mutate(s.feed_id)}>Remove</button>
          </div>
        ))}
        {data.length === 0 && <p className="text-gray-500 text-sm">No sources configured.</p>}
      </div>
    </div>
  )
}
