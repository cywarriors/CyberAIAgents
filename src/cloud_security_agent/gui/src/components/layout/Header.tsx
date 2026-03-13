import { Bell, Settings, LogOut } from 'lucide-react'

export default function Header() {
  return (
    <header className="bg-white shadow-sm border-b border-gray-200 px-6 py-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Cloud Security Posture Management</h1>
        <div className="flex items-center gap-4">
          <button className="p-2 hover:bg-gray-100 rounded-lg transition">
            <Bell size={20} className="text-gray-600" />
          </button>
          <button className="p-2 hover:bg-gray-100 rounded-lg transition">
            <Settings size={20} className="text-gray-600" />
          </button>
          <div className="h-8 w-8 bg-cyan-500 rounded-full flex items-center justify-center text-white text-sm font-bold">
            CS
          </div>
          <button className="p-2 hover:bg-gray-100 rounded-lg transition">
            <LogOut size={20} className="text-gray-600" />
          </button>
        </div>
      </div>
    </header>
  )
}
