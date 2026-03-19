import { BrowserRouter, NavLink, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Decoys from "./pages/Decoys";
import Interactions from "./pages/Interactions";
import Alerts from "./pages/Alerts";
import Coverage from "./pages/Coverage";
import AttackerProfiles from "./pages/AttackerProfiles";
import Settings from "./pages/Settings";

const NAV = [
  { to: "/", label: "Dashboard" },
  { to: "/decoys", label: "Decoys" },
  { to: "/interactions", label: "Interactions" },
  { to: "/alerts", label: "Alerts" },
  { to: "/coverage", label: "Coverage" },
  { to: "/profiles", label: "Attacker Profiles" },
  { to: "/settings", label: "Settings" },
];

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen bg-gray-950 text-gray-100">
        <nav className="w-52 bg-gray-900 p-4 flex flex-col gap-1">
          <div className="text-yellow-400 font-bold mb-4 text-sm">Deception Honeypot</div>
          {NAV.map(({ to, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                `px-3 py-2 rounded text-sm ${isActive ? "bg-yellow-600 text-white" : "hover:bg-gray-800"}`
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>
        <main className="flex-1 overflow-auto p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/decoys" element={<Decoys />} />
            <Route path="/interactions" element={<Interactions />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/coverage" element={<Coverage />} />
            <Route path="/profiles" element={<AttackerProfiles />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
