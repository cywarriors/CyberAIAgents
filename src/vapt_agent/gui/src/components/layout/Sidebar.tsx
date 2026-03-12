import { NavLink } from "react-router-dom";
import { useUIStore } from "../../store/uiStore";
import {
  LayoutDashboard,
  Briefcase,
  Search,
  Radio,
  Bug,
  GitBranch,
  Zap,
  FileText,
  ShieldCheck,
  Settings,
} from "lucide-react";

const links = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/engagements", label: "Engagements", icon: Briefcase },
  { to: "/assets", label: "Asset Discovery", icon: Search },
  { to: "/scans", label: "Scan Monitor", icon: Radio },
  { to: "/findings", label: "Findings", icon: Bug },
  { to: "/attack-paths", label: "Attack Paths", icon: GitBranch },
  { to: "/exploits", label: "Exploitation", icon: Zap },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/compliance", label: "Compliance", icon: ShieldCheck },
  { to: "/admin", label: "Administration", icon: Settings },
];

export default function Sidebar() {
  const open = useUIStore((s) => s.sidebarOpen);

  return (
    <aside
      className={`fixed inset-y-0 left-0 z-30 flex flex-col border-r border-gray-800 bg-gray-950 transition-all ${
        open ? "w-64" : "w-16"
      }`}
    >
      <div className="flex h-14 items-center gap-2 border-b border-gray-800 px-4">
        <ShieldCheck className="h-6 w-6 text-brand-500" />
        {open && (
          <span className="text-lg font-bold tracking-tight text-white">
            VAPT Agent
          </span>
        )}
      </div>

      <nav className="mt-2 flex-1 space-y-1 px-2">
        {links.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${
                isActive
                  ? "bg-brand-600/20 text-brand-500"
                  : "text-gray-400 hover:bg-gray-800 hover:text-white"
              }`
            }
          >
            <l.icon className="h-5 w-5 shrink-0" />
            {open && <span>{l.label}</span>}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
