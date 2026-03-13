import { Link, useLocation } from 'react-router-dom'
import { BarChart3, Shield, AlertCircle, CheckCircle2, Code2, GitCompareArrows, Globe, Settings } from 'lucide-react'

const menuItems = [
  { path: '/', label: 'Posture Dashboard', icon: BarChart3 },
  { path: '/findings', label: 'Finding Browser', icon: AlertCircle },
  { path: '/accounts', label: 'Accounts & Subscriptions', icon: Shield },
  { path: '/compliance', label: 'Compliance Scorecard', icon: CheckCircle2 },
  { path: '/iac', label: 'IaC Pre-Deploy Gate', icon: Code2 },
  { path: '/drift', label: 'Drift Detector', icon: GitCompareArrows },
  { path: '/exposure', label: 'Exposure Monitor', icon: Globe },
  { path: '/admin', label: 'Administration', icon: Settings },
]

export default function Sidebar() {
  const location = useLocation()

  return (
    <aside className="w-64 bg-gray-900 text-white overflow-y-auto">
      <div className="p-6 border-b border-gray-800">
        <h1 className="text-xl font-bold flex items-center gap-2">
          <Shield size={24} className="text-cyan-400" />
          CSPM Agent
        </h1>
        <p className="text-gray-400 text-sm mt-1">Cloud Security Posture</p>
      </div>

      <nav className="p-4 space-y-2">
        {menuItems.map((item) => {
          const Icon = item.icon
          const isActive = location.pathname === item.path
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center gap-3 px-4 py-3 rounded-lg transition ${
                isActive
                  ? 'bg-cyan-600 text-white'
                  : 'text-gray-300 hover:bg-gray-800'
              }`}
            >
              <Icon size={20} />
              <span>{item.label}</span>
            </Link>
          )
        })}
      </nav>
    </aside>
  )
}
