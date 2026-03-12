import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Inbox,
  GitBranch,
  Users,
  BarChart3,
  BookOpen,
  Settings,
  Shield,
} from "lucide-react";

const links = [
  { to: "/dashboard", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/incidents", icon: Inbox, label: "Incidents" },
  { to: "/correlations", icon: GitBranch, label: "Correlations" },
  { to: "/analysts", icon: Users, label: "Analysts" },
  { to: "/analytics", icon: BarChart3, label: "Analytics" },
  { to: "/playbooks", icon: BookOpen, label: "Playbooks" },
  { to: "/admin", icon: Settings, label: "Admin" },
];

export default function Sidebar() {
  return (
    <aside className="fixed inset-y-0 left-0 z-30 flex w-56 flex-col border-r border-gray-800 bg-gray-950">
      <div className="flex h-14 items-center gap-2 px-4 font-bold text-brand-500">
        <Shield className="h-6 w-6" />
        <span className="text-sm">Incident Triage</span>
      </div>
      <nav className="flex-1 space-y-1 px-2 py-4">
        {links.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                isActive
                  ? "bg-brand-600/20 text-brand-400"
                  : "text-gray-400 hover:bg-gray-800 hover:text-white"
              }`
            }
          >
            <Icon className="h-4 w-4" />
            {label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
