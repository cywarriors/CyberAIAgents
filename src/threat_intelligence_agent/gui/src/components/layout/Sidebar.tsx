import { Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Shield,
  FileText,
  Users,
  Rss,
  Clock,
  Target,
  Settings,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { useUIStore } from '../../store/uiStore';

const navItems = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/iocs', label: 'IOC Explorer', icon: Shield },
  { path: '/briefs', label: 'Threat Briefs', icon: FileText },
  { path: '/actors', label: 'Actor Database', icon: Users },
  { path: '/feeds', label: 'Feed Manager', icon: Rss },
  { path: '/lifecycle', label: 'IOC Lifecycle', icon: Clock },
  { path: '/detection', label: 'Detection Mapping', icon: Target },
  { path: '/admin', label: 'Administration', icon: Settings },
];

export default function Sidebar() {
  const location = useLocation();
  const { sidebarOpen, toggleSidebar } = useUIStore();

  return (
    <aside
      className={`fixed left-0 top-0 z-40 h-screen bg-gray-950 text-white transition-all duration-300 ${
        sidebarOpen ? 'w-56' : 'w-16'
      }`}
    >
      {/* Header */}
      <div className="flex h-16 items-center justify-between border-b border-gray-800 px-4">
        <div className="flex items-center gap-3">
          <Shield className="h-8 w-8 text-blue-500" />
          {sidebarOpen && (
            <span className="text-lg font-semibold">Threat Intel</span>
          )}
        </div>
        <button
          onClick={toggleSidebar}
          className="rounded-lg p-1.5 text-gray-400 hover:bg-gray-800 hover:text-white"
        >
          {sidebarOpen ? (
            <ChevronLeft className="h-5 w-5" />
          ) : (
            <ChevronRight className="h-5 w-5" />
          )}
        </button>
      </div>

      {/* Navigation */}
      <nav className="mt-4 px-2">
        <ul className="space-y-1">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path;
            const Icon = item.icon;
            return (
              <li key={item.path}>
                <Link
                  to={item.path}
                  className={`flex items-center gap-3 rounded-lg px-3 py-2.5 transition-colors ${
                    isActive
                      ? 'bg-blue-600 text-white'
                      : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                  }`}
                  title={!sidebarOpen ? item.label : undefined}
                >
                  <Icon className="h-5 w-5 flex-shrink-0" />
                  {sidebarOpen && <span>{item.label}</span>}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Footer */}
      {sidebarOpen && (
        <div className="absolute bottom-4 left-0 right-0 px-4">
          <div className="rounded-lg bg-gray-900 p-3 text-xs text-gray-400">
            <p className="font-medium text-gray-300">SRS-09 Agent</p>
            <p>Threat Intelligence</p>
          </div>
        </div>
      )}
    </aside>
  );
}
