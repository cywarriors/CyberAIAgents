import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useState } from 'react'
import Dashboard from './pages/Dashboard'
import Frameworks from './pages/Frameworks'
import Evidence from './pages/Evidence'
import Gaps from './pages/Gaps'
import AuditPacks from './pages/AuditPacks'
import Sources from './pages/Sources'
import DriftAlerts from './pages/DriftAlerts'
import Settings from './pages/Settings'

const qc = new QueryClient()

const NAV = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'frameworks', label: 'Frameworks' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'gaps', label: 'Gaps' },
  { id: 'audit-packs', label: 'Audit Packs' },
  { id: 'sources', label: 'Sources' },
  { id: 'drift-alerts', label: 'Drift Alerts' },
  { id: 'settings', label: 'Settings' },
]

function App() {
  const [page, setPage] = useState('dashboard')
  const pages: Record<string, JSX.Element> = {
    dashboard: <Dashboard />,
    frameworks: <Frameworks />,
    evidence: <Evidence />,
    gaps: <Gaps />,
    'audit-packs': <AuditPacks />,
    sources: <Sources />,
    'drift-alerts': <DriftAlerts />,
    settings: <Settings />,
  }
  return (
    <QueryClientProvider client={qc}>
      <div className="flex h-screen bg-gray-950 text-gray-100">
        <aside className="w-56 bg-gray-900 border-r border-gray-800 flex flex-col">
          <div className="p-4 font-bold text-green-400 text-sm border-b border-gray-800">
            Compliance & Audit
          </div>
          <nav className="flex-1 overflow-y-auto py-2">
            {NAV.map(n => (
              <button
                key={n.id}
                onClick={() => setPage(n.id)}
                className={`w-full text-left px-4 py-2 text-sm transition-colors ${
                  page === n.id
                    ? 'bg-green-900 text-green-300'
                    : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
                }`}
              >
                {n.label}
              </button>
            ))}
          </nav>
        </aside>
        <main className="flex-1 overflow-y-auto p-6">{pages[page]}</main>
      </div>
    </QueryClientProvider>
  )
}

export default App
