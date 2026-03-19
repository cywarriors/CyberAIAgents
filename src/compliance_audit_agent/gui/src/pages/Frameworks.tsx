import { useQuery } from '@tanstack/react-query'
import api from '../api/client'

export default function Frameworks() {
  const { data = [], isLoading } = useQuery({
    queryKey: ['frameworks'],
    queryFn: () => api.get('/frameworks').then(r => r.data),
  })
  if (isLoading) return <div className="text-gray-400">Loading…</div>
  return (
    <div>
      <h1 className="text-xl font-bold text-green-400 mb-4">Framework Scores</h1>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead><tr className="text-gray-400 border-b border-gray-700">
            <th className="text-left py-2">Framework</th><th className="text-right py-2">Score</th>
            <th className="text-right py-2">Fully Effective</th><th className="text-right py-2">Partial</th>
            <th className="text-right py-2">Ineffective</th><th className="text-left py-2">Org Unit</th>
          </tr></thead>
          <tbody>{(data as any[]).map((f, i) => (
            <tr key={i} className="border-b border-gray-800 hover:bg-gray-800">
              <td className="py-2 text-green-300">{f.framework}</td>
              <td className="py-2 text-right font-mono text-green-400">{(f.score ?? 0).toFixed(1)}%</td>
              <td className="py-2 text-right text-green-400">{f.controls_fully_effective ?? 0}</td>
              <td className="py-2 text-right text-yellow-400">{f.controls_partially_effective ?? 0}</td>
              <td className="py-2 text-right text-red-400">{f.controls_ineffective ?? 0}</td>
              <td className="py-2 text-gray-300">{f.org_unit}</td>
            </tr>
          ))}</tbody>
        </table>
        {data.length === 0 && <p className="text-gray-500 text-sm mt-4">No framework scores yet.</p>}
      </div>
    </div>
  )
}
