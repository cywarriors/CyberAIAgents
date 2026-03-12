import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/layout/Layout";
import DetectionDashboard from "./pages/DetectionDashboard";
import AlertInvestigation from "./pages/AlertInvestigation";
import DetectionCoverage from "./pages/DetectionCoverage";
import RuleManagement from "./pages/RuleManagement";
import AnomalyExplorer from "./pages/AnomalyExplorer";
import PipelineHealth from "./pages/PipelineHealth";
import TuningWorkbench from "./pages/TuningWorkbench";
import Administration from "./pages/Administration";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<DetectionDashboard />} />
        <Route path="/alerts" element={<AlertInvestigation />} />
        <Route path="/coverage" element={<DetectionCoverage />} />
        <Route path="/rules" element={<RuleManagement />} />
        <Route path="/anomalies" element={<AnomalyExplorer />} />
        <Route path="/pipeline" element={<PipelineHealth />} />
        <Route path="/tuning" element={<TuningWorkbench />} />
        <Route path="/admin" element={<Administration />} />
      </Routes>
    </Layout>
  );
}
