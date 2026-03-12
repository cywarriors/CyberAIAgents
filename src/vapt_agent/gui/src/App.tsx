import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/layout/Layout";
import Dashboard from "./pages/Dashboard";
import EngagementManager from "./pages/EngagementManager";
import AssetDiscovery from "./pages/AssetDiscovery";
import ScanMonitor from "./pages/ScanMonitor";
import FindingsExplorer from "./pages/FindingsExplorer";
import AttackPathVisualizer from "./pages/AttackPathVisualizer";
import ExploitationConsole from "./pages/ExploitationConsole";
import ReportBuilder from "./pages/ReportBuilder";
import ComplianceTracker from "./pages/ComplianceTracker";
import Administration from "./pages/Administration";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/engagements" element={<EngagementManager />} />
        <Route path="/assets" element={<AssetDiscovery />} />
        <Route path="/scans" element={<ScanMonitor />} />
        <Route path="/findings" element={<FindingsExplorer />} />
        <Route path="/attack-paths" element={<AttackPathVisualizer />} />
        <Route path="/exploits" element={<ExploitationConsole />} />
        <Route path="/reports" element={<ReportBuilder />} />
        <Route path="/compliance" element={<ComplianceTracker />} />
        <Route path="/admin" element={<Administration />} />
      </Routes>
    </Layout>
  );
}
