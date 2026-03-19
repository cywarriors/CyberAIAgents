import { Routes, Route, NavLink } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Findings from "./pages/Findings";
import Scans from "./pages/Scans";
import SBOMs from "./pages/SBOMs";
import PolicyGates from "./pages/PolicyGates";
import Settings from "./pages/Settings";

const nav = [
  { to: "/", label: "Dashboard" },
  { to: "/findings", label: "Findings" },
  { to: "/scans", label: "Scans" },
  { to: "/sbom", label: "SBOM" },
  { to: "/policy", label: "Policy Gates" },
  { to: "/settings", label: "Settings" },
];

export default function App() {
  return (
    <div className="flex h-screen">
      <aside className="w-56 bg-gray-900 p-4 flex flex-col gap-1">
        <div className="text-indigo-400 font-bold mb-6 text-sm">Code Review Agent</div>
        {nav.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.to === "/"}
            className={({ isActive }) =>
              `px-3 py-2 rounded text-sm ${isActive ? "bg-indigo-600 text-white" : "text-gray-400 hover:text-white"}`
            }
          >
            {n.label}
          </NavLink>
        ))}
      </aside>
      <main className="flex-1 overflow-auto p-6">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/sbom" element={<SBOMs />} />
          <Route path="/policy" element={<PolicyGates />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
}
